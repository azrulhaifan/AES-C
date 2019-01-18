## Academic Project (Cryptography) Nov 2018

Advanced Encryption Standard (AES) is the current standard for encryption. In other words, this standard is used for securing all the communication over the internet. This project implements this standard in C.

AES is based on rounds, this implementation supports 128 bit encryption with 10 rounds. It outputs plaintext after each round while during both encryption and decryption.

Important: One of the most important rule of cryptography is never use your own implementation in production. Please use the open source implementation over these.

### Encrypting and decrypting message (plaintext)
* Download [main](\main)
* Run main while passing key, plaintext, sbox and inverse of sbox files. 
    * For example "./main key_file plaintext_file sbox_file inv_sbox_file"
    * Check sample input files for more info on format
* Main takes input files and uses aes.h to encrypt and decrypt
* Then it compares original message with decrypted message 



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

