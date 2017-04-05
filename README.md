# AES-Rijndael-Encryption
This is an efficient implementation of the AES (Rijndael) encryption algorithm, with key size 128 bits, in C.
When the number of iterations is greater than 1, Cipher Block Chaining (CBC) is used with `IV = C_0 = 0` meaning
the input will be the previous ciphertext XOR the plaintext.

Note: this was programmed for an assignment in CSSE/MA 479 - Cryptography at Rose-Hulman Institute of Technology.

To execute the program, a Makefile is included to make it simple:
```
> make
> ./AES
```

The program reads from the file `aesinput.txt` to get the number of rounds, the number of iterations, the key,
and plaintext. For example, if the contents of `aesinput.txt` is:
```
2
10
2b28ab097eaef7cf15d2154f16a6883c
328831e0435a3137f6309807a88da234
```
Then
```
Number of iterations = 2
Number of rounds     = 10

Key:
2b28ab097eaef7cf15d2154f16a6883c

Plaintext:
328831e0435a3137f6309807a88da234
```
