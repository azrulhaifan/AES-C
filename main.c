#include "aes.h"


int main(int argc, char *argv[])
{
    if(argc < 5) {
        printf("ERROR: expecting 4 paths \"key_file, plaintext_file, sbox_file, inv_sbox_file\"\n");
        exit(-1);
    }

    char* key_file = NULL, *state_file = NULL, *sbox_file = NULL, *inv_sbox_file = NULL;
    key_file = argv[1];
    state_file = argv[2];
    sbox_file = argv[3];
    inv_sbox_file = argv[4];

    initialize(key_file, state_file, sbox_file, inv_sbox_file);
    encrypt();
    decrypt();
    assertStateIsOrigMesg();

    printf("\nProgram ended Successfully\n");
    return 0;
}