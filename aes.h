
#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
# include <assert.h> 

// Functions
// Initialize key, sbox and state
void initialize(char * key_file, char * state_file, char* sbox_file, char* inv_sbox_file);
// Encrypt state using AES scheme
void encrypt();
// Decrypt state using DES scheme
void decrypt();
// Get current state, (free after using it)
uint8_t * getState();
// Print current state
void printState();
// Print sub keys generated from key expansion
void printSubKeys();
// Assert if state is original message
void assertStateIsOrigMesg();


#endif
