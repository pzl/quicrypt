package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/dsnet/compress/bzip2"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh/terminal"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func decrypt(enc io.Reader) io.Reader {
	var source io.Reader
	source = bufio.NewReader(enc)

	// de-PGP armor if needed
	head, err := source.(*bufio.Reader).Peek(11)
	check(err)
	if isArmored(head) {
		unarmor, err := armor.Decode(source)
		check(err)
		source = unarmor.Body
	}

	// decrypt, ask for password
	failed := false
	msg, err := openpgp.ReadMessage(source, nil,
		func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			if failed {
				// function will just be called again and
				// again for bad passwords. Forever
				// return an error to break out
				fmt.Fprintf(os.Stderr, "\nincorrect. ")
			}
			failed = true
			fmt.Fprintf(os.Stderr, "decrypt password: ")
			return terminal.ReadPassword(int(syscall.Stdin))
		}, nil)
	fmt.Fprint(os.Stderr, "\n")
	check(err)

	return msg.UnverifiedBody
}

func isArmored(data []byte) bool {
	return bytes.Equal(data[:11], []byte("-----BEGIN "))
}

func isTar(data []byte) bool {
	return string(data[0:2]) == "BZ"
}

func encrypt(plainText io.Reader, pass []byte, compress bool, asciiArmor bool) []byte {
	var w io.Writer
	encBuffer := bytes.NewBuffer(nil)
	w = encBuffer
	if asciiArmor {
		armored, err := armor.Encode(encBuffer, "PGP MESSAGE", nil)
		check(err)
		w = armored
	}

	var compression packet.CompressionAlgo
	if compress {
		// note that we can decrypt bzip2
		// https://github.com/golang/crypto/blob/master/openpgp/packet/compressed.go#L55
		// but we can't encrypt with it baked in
		compression = packet.CompressionZLIB
	} else {
		compression = packet.CompressionNone
	}

	// encrypted data->writer, backed by encBuffer buffer (opt. armor passthrough)
	encrypter, err := openpgp.SymmetricallyEncrypt(w, pass, &openpgp.FileHints{
		IsBinary: false, /* @todo write to file */
		FileName: "_CONSOLE",
	}, &packet.Config{
		//DefaultHash:            crypto,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: compression,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
	})
	check(err)

	io.Copy(encrypter, plainText)
	encrypter.Close()

	if asciiArmor {
		w.(io.WriteCloser).Close()
	}

	return encBuffer.Bytes()
}

func tarball(startDir string) io.Reader {
	// tar -cj

	buf := bytes.NewBuffer(nil)

	bz, err := bzip2.NewWriter(buf, &bzip2.WriterConfig{
		Level: 9,
	})
	check(err)
	defer bz.Close()

	tarW := tar.NewWriter(bz)
	defer tarW.Close()

	// write to tarW from files in startDir
	filepath.Walk(startDir, func(file string, fi os.FileInfo, err error) error {
		check(err)

		header, err := tar.FileInfoHeader(fi, fi.Name())
		check(err)
		header.Name = file

		check(tarW.WriteHeader(header))

		if !fi.Mode().IsRegular() { // only write contents for normal files
			return nil
		}

		f, err := os.Open(file)
		check(err)

		_, err = io.Copy(tarW, f) // actual writing here
		check(err)

		f.Close() //defer would cause each file handle to wait until all completed
		return nil
	})

	return buf
}
func untar(source io.Reader) {
	// tar -xjf

	bz, err := bzip2.NewReader(source, nil)
	check(err)
	defer bz.Close()

	tarR := tar.NewReader(bz)

	for {
		header, err := tarR.Next()

		if err == io.EOF {
			return
		}
		check(err)
		if header == nil {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			_, err := os.Stat(header.Name)
			if err != nil && !os.IsNotExist(err) {
				check(err)
			}
			check(os.MkdirAll(header.Name, 0755))
		case tar.TypeReg:
			f, err := os.OpenFile(header.Name, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			check(err)

			_, err = io.Copy(f, tarR)
			check(err)

			f.Close()
		}
	}

}

func isEncrypted(filename string) bool {
	fi, err := os.Stat(filename)
	check(err)

	if fi.IsDir() {
		return false
	}

	f, err := os.Open(filename)
	check(err)
	defer f.Close()

	buf := make([]byte, 11)
	n, err := io.ReadFull(f, buf)
	if err != io.EOF {
		check(err)
	}
	if n == 0 {
		fmt.Fprint(os.Stderr, "read no bytes")
	}

	if isArmored(buf) {
		return true
	}

	// gpg symmetric 8c0d 0409 0302 https://github.com/file/file/blob/master/magic/Magdir/gnu#L136-L147
	//               8c0d 0407 0302
	// or us:        c32e 0409 0308
	if bytes.Equal(buf[0:2], []byte{0x8c, 0x0d}) || bytes.Equal(buf[0:2], []byte{0xc3, 0x2e}) {
		if buf[2] == 0x04 && buf[4] == 0x03 {
			return true
		}
	}
	return false
}

func main() {

	// check for help and print usage
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Print("Usage: quicrypt FILE/FOLDER\n")
		if len(os.Args) < 2 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	filename := os.Args[1]

	// check that file/path exists and can be read, not empty, etc
	fi, err := os.Stat(filename)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "%s not found\n", filename)
		os.Exit(1)
	}
	check(err)

	if isEncrypted(filename) {
		f, err := os.Open(filename)
		check(err)
		data := decrypt(f)

		//detect if decrypted thing is a tar
		buf := bufio.NewReader(data)
		head, err := buf.Peek(2)
		check(err)
		if isTar(head) {
			untar(buf)
		} else {
			io.Copy(os.Stdout, buf)
		}

		//remove original file
		check(os.RemoveAll(filename))
	} else {
		// get password to use
		fmt.Fprint(os.Stderr, "Enter password to encrypt: ")
		pass, err := terminal.ReadPassword(int(syscall.Stdin))
		check(err)
		fmt.Fprint(os.Stderr, "\nRe-Enter password: ")
		repass, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Fprint(os.Stderr, "\n")
		check(err)
		if !bytes.Equal(pass, repass) {
			fmt.Fprint(os.Stderr, "Passwords did not match")
			os.Exit(1)
		}

		var f io.Reader
		if fi.IsDir() {
			f = tarball(filename)
		} else {
			f, err = os.Open(filename)
			check(err)
		}

		data := encrypt(f, pass, !fi.IsDir(), false)

		output, err := os.OpenFile(strings.TrimRight(filename, "/")+".gpg", os.O_CREATE|os.O_RDWR, 0644)
		check(err)
		defer output.Close()
		output.Write(data)

		// remove original (securely?)
		check(os.RemoveAll(filename))
	}
	return
}
