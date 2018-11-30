package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pzl/cryptlib"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
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

	encrypted, err := cryptlib.IsEncrypted(filename)
	check(err)

	if encrypted {
		f, err := os.Open(filename)
		check(err)
		data, err := cryptlib.Decrypt(f)
		check(err)

		//detect if decrypted thing is a tar
		buf := bufio.NewReader(data)
		head, err := buf.Peek(2)
		check(err)
		if cryptlib.IsTar(head) {
			cryptlib.Untar(buf)
		} else {
			io.Copy(os.Stdout, buf)
		}

		//remove original file
		check(os.RemoveAll(filename))
	} else {
		// get password to use
		pass, err := cryptlib.PassPrompt()
		check(err)

		var f io.Reader
		if fi.IsDir() {
			f, err = cryptlib.Tarball(filename)
			check(err)
		} else {
			f, err = os.Open(filename)
			check(err)
		}

		data, err := cryptlib.Encrypt(f, pass, !fi.IsDir(), false)
		check(err)

		output, err := os.OpenFile(strings.TrimRight(filename, "/")+".gpg", os.O_CREATE|os.O_RDWR, 0644)
		check(err)
		defer output.Close()
		output.Write(data)

		// remove original (securely?)
		check(os.RemoveAll(filename))
	}
	return
}
