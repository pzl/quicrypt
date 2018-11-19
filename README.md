Quicrypt
========

A quick and simple encrypt and decrypt utility. 


Usage
-----

`quicrypt FILE/FOLDER`

*quicrypt* accepts a single argument: something to en/de-crypt.

If you pass in a normal file (text, image, whatever), it will encrypt it and replace it with `filename.gpg`. If you pass in a directory, it will replace the whole directory with `dirname.gpg`.

If you pass in an encrypted file (created via one of the above), it will decrypt, and recreate the file or directory, and put them back.


History
-------

I had a folder that I kept family documents in. I wanted to keep it encrypted while the machine was running, and to be able to move around a network safely. I created a bash wrapping script around `gpg -C`, `tar`, and the like, to encrypt and decrypt.

I started using some systems where I didn't have some of the needed utilities for this little wrapper script available, so I ported it to `go`, so I can just grab my `quicrypt` bin to shuffle these files around.

Old script:

```bash
command -v gpg >/dev/null 2>&1 || { echo "GPG must be installed" >&2; exit 1; }


#get input filename and make sure it can be used
readonly FILE="${1%/}" #%/ to remove any trailing slashes (esp on directories)
if [ ! -e "$FILE" -o ! -f "$FILE" -a ! -d "$FILE"  -o ! -r "$FILE" -o ! -s "$FILE" ]; then
    echo "Cannot use "$FILE", might not be readable, or might be empty" >&2
    exit 1
fi

# set preferred pinentry mode. pinentry-curses and pinentry-tty are console-based
if file -b "$FILE" | grep "GPG.*encrypted" >/dev/null 2>&1; then
    #input file is already encrypted, we are decrypting
    echo "decrypting.."
    gpg -d "${FILE}"

    #if bzipped: Not done. was probably a dir
    if file -b "${FILE%.gpg}" | grep "^bzip2" >/dev/null 2>&1; then
        echo "expanding directory.."
        tar -xjf "${FILE%.gpg}"
    fi

    rm -rf "$FILE"
else
    echo "Encrypting ${FILE}."

    #directories cannot be `gpg`d directly. tar first
    if [ -d "$FILE" ];then
        tar -cj "$FILE" | gpg -c --cipher-algo aes256 -z 0 -o "${FILE}.gpg"
    else
        gpg -c --cipher-algo aes256  --compress-algo bzip2 -z 9 "${FILE}"
    fi
    rm -rf "$FILE"
fi

```


License
--------

MIT, Copyright (c) 2018 Dan Panzarella