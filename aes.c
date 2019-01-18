#include "aes.h"


// Macros
#define KEY_SIZE 4
#define STATE_SIZE 4
#define SBOX_SIZE 16
#define MAX_ROUNDS 11
#define SBOX_LOOKUP(lookup_box, num) lookup_box[(num) >> 4][(num) & 0x0F];


// Global state
uint8_t static key[KEY_SIZE][KEY_SIZE];
uint8_t static state[STATE_SIZE][STATE_SIZE];
uint8_t static orig_msg[STATE_SIZE][STATE_SIZE];
uint8_t static sbox[SBOX_SIZE][SBOX_SIZE];
uint8_t static inv_sbox[SBOX_SIZE][SBOX_SIZE];
uint8_t static sub_keys [MAX_ROUNDS][KEY_SIZE][KEY_SIZE];
int initialize_called;


// Private Headers
void _generateSubkeys();
void _initFromFile(int size, uint8_t matrix[size][size], char * file_name);
void _addRoundKey(int round);
void _shiftRows();
void _invShiftRows();
void _helperShiftRow(int row);
void _subByte(uint8_t sbox_to_use[SBOX_SIZE][SBOX_SIZE]);
void _mixColumns();
void _invMixColumns();
// Cite https://en.wikipedia.org/wiki/Finite_field_arithmetic
uint8_t _gmult(uint8_t a, uint8_t b);
void _printMatrix(int size, uint8_t matrix[size][size]);


/********************************************************/
/*Public Functions***************************************/
/********************************************************/


void initialize(char * key_file, char * state_file, char* sbox_file, char* inv_sbox_file) {
    _initFromFile(KEY_SIZE, key, key_file);
    _initFromFile(STATE_SIZE, state, state_file);
    _initFromFile(SBOX_SIZE, sbox, sbox_file);
    _initFromFile(SBOX_SIZE, inv_sbox, inv_sbox_file);
    memcpy(orig_msg, state, sizeof(uint8_t) * STATE_SIZE * STATE_SIZE);
    _generateSubkeys();
    initialize_called = 1;
}


void encrypt() {

    assert(initialize_called);

    printf("\nENCRYPTION PROCESS\n");
    printf("------------------\n");

    // start at 0 to print plaintext
    int curr_round = 0;
    printState(curr_round);


    // initial round
    _addRoundKey(curr_round);
    curr_round += 1;
    printState(curr_round);

    // 9 rounds
    while (curr_round < 10) {
        _subByte(sbox);
        _shiftRows();
        _mixColumns();
        _addRoundKey(curr_round);
        curr_round += 1;
        printState(curr_round);
    }

    // final round
    _subByte(sbox);
    _shiftRows();
    _addRoundKey(curr_round);
    curr_round += 1;
    printState(curr_round);
}


void decrypt() {
    printf("\n\nDECRYPTION PROCESS\n");
    printf("------------------\n");

    // start at 11 to print cipher first
    int curr_round = MAX_ROUNDS;

     printState(curr_round);
    curr_round -= 1;

    // final round
    _addRoundKey(curr_round);
    _invShiftRows();
    _subByte(inv_sbox);
    printState(curr_round);
    curr_round -= 1;

    // 9 rounds
    while (curr_round > 0) {
        _addRoundKey(curr_round);
        _invMixColumns();
        _invShiftRows();
        _subByte(inv_sbox);
        printState(curr_round);
        curr_round -= 1;
    }

    // initial round
    _addRoundKey(curr_round);
    printState(curr_round);
    printf("\nEND of Decryption\n------------------\n");
}


uint8_t * getState() {
    uint8_t * state_array = malloc(sizeof(uint8_t) * STATE_SIZE * STATE_SIZE);
    for(int r=0; r<STATE_SIZE; r++) {
        for(int c=0; c<STATE_SIZE; c++) {
            state_array[r * STATE_SIZE + c] = state[r][c];
        }
    }
    return state_array;
}


void printState(int curr_round) {
    if(curr_round == 0)
        printf("\nPlain Text:\n");
    else if(curr_round == 1)
        printf("\nInital Round (Only AddRoundkey):\n-----------\n");
    else if(curr_round == MAX_ROUNDS)
        printf("\nCipherText (Last Round):\n");
    else
        printf("\nRound %d\n-----------\n", curr_round-1);
    for(int c=0; c<STATE_SIZE; c++) {
        for(int r=0; r<STATE_SIZE; r++) {
            printf("%02x ", state[r][c]);
        }
        printf("  ");
    }
    printf("\n");
}


void printSubKeys() {
    printf("\nKey Schedule:\n");
    for(int k=0; k<MAX_ROUNDS; k++) {
        for(int c=0; c<STATE_SIZE; c++) {
            for(int r=0; r<STATE_SIZE; r++) {
                printf("%x", sub_keys[k][r][c]);
            }
            printf(",");
        }
        printf("\n");
    }
    printf("\n");
}


void assertStateIsOrigMesg() {
    for(int r=0; r<STATE_SIZE; r++) {
        for(int c=0; c<STATE_SIZE; c++) {
            if (state[r][c] != orig_msg[r][c]){
                printf("\nAssertion Failure: State and original message are not same!\n");
                assert(state[r][c] == orig_msg[r][c]);
            }
        }
    }
    printf("\nAssertion Passed: State is same as original message\n");
}


/********************************************************/
/*Helper Functions***************************************/
/********************************************************/


void _generateSubkeys() {

    int curr_round = 0;

    // copy key for intial round round
    memcpy(sub_keys[curr_round], key, sizeof(uint8_t) * STATE_SIZE * STATE_SIZE);
    curr_round += 1;

    // round constant
    uint8_t rci[11] = {0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

    while (curr_round < MAX_ROUNDS) {

        // copy previous rounds last column and move top byte to the bottom
        sub_keys[curr_round][0][0] = sub_keys[curr_round-1][1][STATE_SIZE-1];
        sub_keys[curr_round][1][0] = sub_keys[curr_round-1][2][STATE_SIZE-1];
        sub_keys[curr_round][2][0] = sub_keys[curr_round-1][3][STATE_SIZE-1];
        sub_keys[curr_round][3][0] = sub_keys[curr_round-1][0][STATE_SIZE-1];
        
        // Map first column using sbox
        sub_keys[curr_round][0][0] = SBOX_LOOKUP(sbox, sub_keys[curr_round][0][0]);
        sub_keys[curr_round][1][0] = SBOX_LOOKUP(sbox, sub_keys[curr_round][1][0]);
        sub_keys[curr_round][2][0] = SBOX_LOOKUP(sbox, sub_keys[curr_round][2][0]);
        sub_keys[curr_round][3][0] = SBOX_LOOKUP(sbox, sub_keys[curr_round][3][0]);

        // apply round constant
        sub_keys[curr_round][0][0] ^= rci[curr_round];

        // xor with previous rounds first column
        sub_keys[curr_round][0][0] ^= sub_keys[curr_round-1][0][0];
        sub_keys[curr_round][1][0] ^= sub_keys[curr_round-1][1][0];
        sub_keys[curr_round][2][0] ^= sub_keys[curr_round-1][2][0];
        sub_keys[curr_round][3][0] ^= sub_keys[curr_round-1][3][0];

        // other 3 columns
        for (int c=1; c<STATE_SIZE; c++){
            for (int r=0; r<STATE_SIZE; r++){
                // XOR previous column with previous round column c
                sub_keys[curr_round][r][c] = sub_keys[curr_round][r][c-1] ^ sub_keys[curr_round-1][r][c];
            }
        }
        curr_round += 1;
    }

    printSubKeys();
}


void _initFromFile(int size, uint8_t matrix[size][size], char * file_name) {
    FILE *file;
    if ((file = fopen(file_name, "r")) == NULL){
        printf("Error! opening file");
        exit(1);
    }

    // variable to read value
    unsigned int input_var;
    if (size == STATE_SIZE) {  // key and plaintext
        for(int c=0; c<size; c++) {
            for(int r=0; r<size; r++) {
                fscanf(file, "%x", &input_var);
                // Each value should be 1 byte
                assert(input_var<=255);
                matrix[r][c] = (uint8_t)input_var;
            }
        }
    }    
    else {  // sbox
        for(int r=0; r<size; r++) {
            for(int c=0; c<size; c++) {
                fscanf(file, "%x", &input_var);
                // Each value should be 1 byte
                assert(input_var<=255);
                matrix[r][c] = (uint8_t)input_var;
            }
        }
    }
    fclose(file);
}


void _addRoundKey(int round) {
    for(int r=0; r<STATE_SIZE; r++) {
        for (int c=0; c<STATE_SIZE; c++) {
            state[r][c] ^= sub_keys[round][r][c];
        }
    }
}


void _shiftRows() {
    // shift row 1 by 1 byte
    _helperShiftRow(1);
    // shift row 2 by 2 byte
    _helperShiftRow(2);
    _helperShiftRow(2);
    // shift row 3 by 3 byte
    _helperShiftRow(3);
    _helperShiftRow(3);
    _helperShiftRow(3);
}


void _invShiftRows() {
    // shift row 1 by 3 bytes
    _helperShiftRow(1);
    _helperShiftRow(1);
    _helperShiftRow(1);
    // shift row 2 by 2 bytes
    _helperShiftRow(2);
    _helperShiftRow(2);
    // shift row 3 by 1 byte
    _helperShiftRow(3);
}


void _helperShiftRow(int row) {
    // shift row by 1 byte
    uint8_t temp = state[row][0];
    state[row][0] = state[row][1];
    state[row][1] = state[row][2];
    state[row][2] = state[row][3];
    state[row][3] = temp;
}


void _subByte(uint8_t sbox_to_use[SBOX_SIZE][SBOX_SIZE]) {
    for(int r=0; r<STATE_SIZE; r++) {
        for (int c=0; c<STATE_SIZE; c++) {
            state[r][c] = SBOX_LOOKUP(sbox_to_use, state[r][c]);
        }
    }
}


void _mixColumns() {
    uint8_t temp1, temp2, temp3, temp4;
    // Multiply each column of state with diffuision matrix
    for (int c=0; c<STATE_SIZE; c++) {
        temp1 = _gmult(2, state[0][c]) ^ _gmult(3, state[1][c]) ^ _gmult(1, state[2][c]) ^ _gmult(1, state[3][c]);
        temp2 = _gmult(1, state[0][c]) ^ _gmult(2, state[1][c]) ^ _gmult(3, state[2][c]) ^ _gmult(1, state[3][c]);
        temp3 = _gmult(1, state[0][c]) ^ _gmult(1, state[1][c]) ^ _gmult(2, state[2][c]) ^ _gmult(3, state[3][c]);
        temp4 = _gmult(3, state[0][c]) ^ _gmult(1, state[1][c]) ^ _gmult(1, state[2][c]) ^ _gmult(2, state[3][c]);

        state[0][c] = temp1;
        state[1][c] = temp2;
        state[2][c] = temp3;
        state[3][c] = temp4;
    }
}


void _invMixColumns() {
    uint8_t temp1, temp2, temp3, temp4;
    // Multiply each column of state with diffuision matrix
    for (int c=0; c<STATE_SIZE; c++) {
        temp1 = _gmult(0x0e, state[0][c]) ^ _gmult(0x0b, state[1][c]) ^ _gmult(0x0d, state[2][c]) ^ _gmult(0x09, state[3][c]);
        temp2 = _gmult(0x09, state[0][c]) ^ _gmult(0x0e, state[1][c]) ^ _gmult(0x0b, state[2][c]) ^ _gmult(0x0d, state[3][c]);
        temp3 = _gmult(0x0d, state[0][c]) ^ _gmult(0x09, state[1][c]) ^ _gmult(0x0e, state[2][c]) ^ _gmult(0x0b, state[3][c]);
        temp4 = _gmult(0x0b, state[0][c]) ^ _gmult(0x0d, state[1][c]) ^ _gmult(0x09, state[2][c]) ^ _gmult(0x0e, state[3][c]);

        // values are stored in temp so values don't change in mid-calculation
        state[0][c] = temp1;
        state[1][c] = temp2;
        state[2][c] = temp3;
        state[3][c] = temp4;
    }
}


// https://en.wikipedia.org/wiki/Finite_field_arithmetic
uint8_t _gmult(uint8_t a, uint8_t b) {
	uint8_t p = 0; /* the product of the multiplication */
	while (a && b) {
            if (b & 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
                p ^= a; /* since we're in GF(2^m), addition is an XOR */

            if (a & 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
                a = (a << 1) ^ 0x11b; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) – you can change it but it must be irreducible */
            else
                a <<= 1; /* equivalent to a*2 */
            b >>= 1; /* equivalent to b // 2 */
	}
	return p;
}


void _printMatrix(int size, uint8_t matrix[size][size]) {
    printf("\n");
    for(int r=0; r<size; r++) {
        for(int c=0; c<size; c++) {
            printf("%02x ", matrix[r][c]);
        }
        printf("\n");
    }
    printf("\n");
}