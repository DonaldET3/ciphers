Opal RC6

This program encrypts and decrypts files. The password and nonce are input
through standard input.

The password is not translated to a common encoding before being used as the
key, so the text encoding used by the encrypting computer and the decrypting
computer must be the same. It is recommended that the system locale be set to
one that uses UTF-8 for maximum portability. GNU/Linux is set to UTF-8 by
default. FreeBSD is set to ASCII by default, which works with UTF-8 if you use
an American keyboard.

By default, the program is in encryption mode. For decryption mode, mention the
-d option.

The number in the program name after the dash specifies how many bits per word
the program uses.

__options__
h: output help and exit
d: decryption mode
e: re-encryption mode
r: number of rounds to encrypt file data (default: 34)
x: password and nonce input are interpreted as hexadecimal

The input and output file names are prompted for. In decryption mode, the file
is checked for a file name before prompting for an output file name.

The number of rounds does not need to be provided when decrypting a file.

You should enter information you can't remember to be used as the nonce.
Pressing random keys on your keyboard should work quite well.

The data is not checked for errors. A hash should be computed seperately to
verify the integrity of the data.

block cipher mode: CTR, then ECB


FILE FORMAT

null-terminated magic string
file version byte
number of rounds (hexadecimal string)
nonce block
password check block
encrypted file name (null-terminated)
encrypted data

The password check is an encrypted clear block.

The data starts just after the next block boundary after the file name.
