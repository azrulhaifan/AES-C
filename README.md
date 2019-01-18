

### Language and structure:
* Source code is in C
* Main takes input files and uses aes.h to encrypt and decrypt
* Then it compares original message with decrypted message


### Makefile:
* make: to create executable called "main"
* make clean: to remove created files


### Running main:
* main executable takes 4 arguments/paths:
* to run main: "./main key_file state_file sbox_file inv_sbox_file"


### Structure of AES (for encryption):

* Initial Round
    * AddRoundKey
* Round 1 to 9
    * SubBytes
    * ShiftRows
    * MixColumns
    * AddRoundKey
* Cipher Text (Last Round)
    * SubBytes
    * ShiftRows
    * AddRoundKey

### Cite:
* Took finite field multiplication from [here](https://en.wikipedia.org/wiki/Finite_field_arithmetic)
* See func '_gmult' in aes.c

