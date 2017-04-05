/**
 * Author: Austin Derrow-Pinion
 * Class: CSSE/MA 479 - Cryptography
 * Purpose: Program an implementation of 128-bit AES encryption.
 * Date: 04/06/2017
 *
 * I tried to reduce as many branching instructions as possible to keep
 * the efficiency the best I can, so sorry about the unrolled loops.
 * The MixColumns stage is calculated very efficiently using only bit-wise
 * operations for the matrix multiplication.
 * Rcon uses a lookup table rather can doing 2 shifts, an AND, and a multiply.
 * ByteSub and ShiftRows stages are combined into one to reduce # instructions.
 */

#include <stdio.h>
#include <stdlib.h>

/* Rijndael reducing polynomial */
#define X 0x1b

/**
 * Instead of using an if statement, this eliminates a branch instruction
 * by simply doing bit-wise operations.
 * Also removes jumps by making this inline.
 */
#define multiply_X(c) ((c << 1) ^ (((c >> 7) & 1) * X))

/* S-Box used for byte substitution */
unsigned char sbox[16][16] = {
  /*0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F */
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

/* Instead of doing two shifts, an AND, and a multiplication for each
 * iteration, this lookup table is used to only use a single ADD.
 */
unsigned char rcon[64] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
  0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
  0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
  0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
  0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
  0x36, 0x6c, 0xd8, 0xab };

/* Index representing current rcon value to use in the rcon array */
unsigned char rcon_i = 0;

/**
 * This function does both the byteSub and shiftRows stage
 */
void byteSub(unsigned char arr[4][4]) {
  unsigned char temp;

  // 1st row shifted 0
  arr[0][0] = sbox[arr[0][0] >> 4][arr[0][0] & 0xF];
  arr[0][1] = sbox[arr[0][1] >> 4][arr[0][1] & 0xF];
  arr[0][2] = sbox[arr[0][2] >> 4][arr[0][2] & 0xF];
  arr[0][3] = sbox[arr[0][3] >> 4][arr[0][3] & 0xF];

  // 2nd row shifted 1
  temp = arr[1][0];
  arr[1][0] = sbox[arr[1][1] >> 4][arr[1][1] & 0xF];
  arr[1][1] = sbox[arr[1][2] >> 4][arr[1][2] & 0xF];
  arr[1][2] = sbox[arr[1][3] >> 4][arr[1][3] & 0xF];
  arr[1][3] = sbox[temp >> 4][temp & 0xF];

  // 3rd row shifted 2
  temp = arr[2][0];
  arr[2][0] = sbox[arr[2][2] >> 4][arr[2][2] & 0xF];
  arr[2][2] = sbox[temp >> 4][temp & 0xF];
  temp = arr[2][1];
  arr[2][1] = sbox[arr[2][3] >> 4][arr[2][3] & 0xF];
  arr[2][3] = sbox[temp >> 4][temp & 0xF];

  // 4th row shifted 3
  temp = arr[3][3];
  arr[3][3] = sbox[arr[3][2] >> 4][arr[3][2] & 0xF];
  arr[3][2] = sbox[arr[3][1] >> 4][arr[3][1] & 0xF];
  arr[3][1] = sbox[arr[3][0] >> 4][arr[3][0] & 0xF];
  arr[3][0] = sbox[temp >> 4][temp & 0xF];
}

/**
 * MixColumn stage does matrix multiplication.
 */
void mixColumn(unsigned char arr[4][4]) {
  // data for 1st column
  unsigned char temp[4][3];
  temp[0][0] = arr[0][0];
  temp[0][1] = multiply_X(arr[0][0]);
  temp[0][2] = temp[0][1] ^ temp[0][0];
  temp[1][0] = arr[1][0];
  temp[1][1] = multiply_X(arr[1][0]);
  temp[1][2] = temp[1][0] ^ temp[1][1];
  temp[2][0] = arr[2][0];
  temp[2][1] = multiply_X(arr[2][0]);
  temp[2][2] = temp[2][0] ^ temp[2][1];
  temp[3][0] = arr[3][0];
  temp[3][1] = multiply_X(arr[3][0]);
  temp[3][2] = temp[3][0] ^ temp[3][1];

  // 1st column assignment
  arr[0][0] = temp[0][1] ^ temp[1][2] ^ temp[2][0] ^ temp[3][0];
  arr[1][0] = temp[0][0] ^ temp[1][1] ^ temp[2][2] ^ temp[3][0];
  arr[2][0] = temp[0][0] ^ temp[1][0] ^ temp[2][1] ^ temp[3][2];
  arr[3][0] = temp[0][2] ^ temp[1][0] ^ temp[2][0] ^ temp[3][1];

  // data for 2nd column
  temp[0][0] = arr[0][1];
  temp[0][1] = multiply_X(arr[0][1]);
  temp[0][2] = temp[0][1] ^ temp[0][0];
  temp[1][0] = arr[1][1];
  temp[1][1] = multiply_X(arr[1][1]);
  temp[1][2] = temp[1][0] ^ temp[1][1];
  temp[2][0] = arr[2][1];
  temp[2][1] = multiply_X(arr[2][1]);
  temp[2][2] = temp[2][0] ^ temp[2][1];
  temp[3][0] = arr[3][1];
  temp[3][1] = multiply_X(arr[3][1]);
  temp[3][2] = temp[3][0] ^ temp[3][1];

  // 2nd column assignment
  arr[0][1] = temp[0][1] ^ temp[1][2] ^ temp[2][0] ^ temp[3][0];
  arr[1][1] = temp[0][0] ^ temp[1][1] ^ temp[2][2] ^ temp[3][0];
  arr[2][1] = temp[0][0] ^ temp[1][0] ^ temp[2][1] ^ temp[3][2];
  arr[3][1] = temp[0][2] ^ temp[1][0] ^ temp[2][0] ^ temp[3][1];

  // data for 3rd column
  temp[0][0] = arr[0][2];
  temp[0][1] = multiply_X(arr[0][2]);
  temp[0][2] = temp[0][1] ^ temp[0][0];
  temp[1][0] = arr[1][2];
  temp[1][1] = multiply_X(arr[1][2]);
  temp[1][2] = temp[1][0] ^ temp[1][1];
  temp[2][0] = arr[2][2];
  temp[2][1] = multiply_X(arr[2][2]);
  temp[2][2] = temp[2][0] ^ temp[2][1];
  temp[3][0] = arr[3][2];
  temp[3][1] = multiply_X(arr[3][2]);
  temp[3][2] = temp[3][0] ^ temp[3][1];

  // 3rd column assignment
  arr[0][2] = temp[0][1] ^ temp[1][2] ^ temp[2][0] ^ temp[3][0];
  arr[1][2] = temp[0][0] ^ temp[1][1] ^ temp[2][2] ^ temp[3][0];
  arr[2][2] = temp[0][0] ^ temp[1][0] ^ temp[2][1] ^ temp[3][2];
  arr[3][2] = temp[0][2] ^ temp[1][0] ^ temp[2][0] ^ temp[3][1];

  // data for 4th column
  temp[0][0] = arr[0][3];
  temp[0][1] = multiply_X(arr[0][3]);
  temp[0][2] = temp[0][1] ^ temp[0][0];
  temp[1][0] = arr[1][3];
  temp[1][1] = multiply_X(arr[1][3]);
  temp[1][2] = temp[1][0] ^ temp[1][1];
  temp[2][0] = arr[2][3];
  temp[2][1] = multiply_X(arr[2][3]);
  temp[2][2] = temp[2][0] ^ temp[2][1];
  temp[3][0] = arr[3][3];
  temp[3][1] = multiply_X(arr[3][3]);
  temp[3][2] = temp[3][0] ^ temp[3][1];

  // 4th column assignment
  arr[0][3] = temp[0][1] ^ temp[1][2] ^ temp[2][0] ^ temp[3][0];
  arr[1][3] = temp[0][0] ^ temp[1][1] ^ temp[2][2] ^ temp[3][0];
  arr[2][3] = temp[0][0] ^ temp[1][0] ^ temp[2][1] ^ temp[3][2];
  arr[3][3] = temp[0][2] ^ temp[1][0] ^ temp[2][0] ^ temp[3][1];
}

/**
 * Adds the given key to the given arr. Addition in this field is simply
 * done using an XOR.
 */
void addRoundKey(unsigned char arr[4][4], unsigned char key[4][4]) {
  // 1st row
  arr[0][0] ^= key[0][0];
  arr[0][1] ^= key[0][1];
  arr[0][2] ^= key[0][2];
  arr[0][3] ^= key[0][3];

  // 2nd row
  arr[1][0] ^= key[1][0];
  arr[1][1] ^= key[1][1];
  arr[1][2] ^= key[1][2];
  arr[1][3] ^= key[1][3];

  // 3rd row
  arr[2][0] ^= key[2][0];
  arr[2][1] ^= key[2][1];
  arr[2][2] ^= key[2][2];
  arr[2][3] ^= key[2][3];

  // 4th row
  arr[3][0] ^= key[3][0];
  arr[3][1] ^= key[3][1];
  arr[3][2] ^= key[3][2];
  arr[3][3] ^= key[3][3];
}

/**
 * Computes the next round key as defined in the AES algorithm.
 */
void nextRoundKey(unsigned char key[4][4]) {
  // rotate last column
  unsigned char temp[4] = { key[1][3], key[2][3], key[3][3], key[0][3] };

  // s-box on the rotated last column
  temp[0] = sbox[temp[0] >> 4][temp[0] & 0xF];
  temp[1] = sbox[temp[1] >> 4][temp[1] & 0xF];
  temp[2] = sbox[temp[2] >> 4][temp[2] & 0xF];
  temp[3] = sbox[temp[3] >> 4][temp[3] & 0xF];

  // 1st row of new round key
  key[0][0] ^= temp[0] ^ rcon[(rcon_i++) & 0x1f];
  key[0][1] ^= key[0][0];
  key[0][2] ^= key[0][1];
  key[0][3] ^= key[0][2];

  // 2nd row of new round key
  key[1][0] ^= temp[1];
  key[1][1] ^= key[1][0];
  key[1][2] ^= key[1][1];
  key[1][3] ^= key[1][2];

  // 3rd row of new round key
  key[2][0] ^= temp[2];
  key[2][1] ^= key[2][0];
  key[2][2] ^= key[2][1];
  key[2][3] ^= key[2][2];

  // 4th row of new round key
  key[3][0] ^= temp[3];
  key[3][1] ^= key[3][0];
  key[3][2] ^= key[3][1];
  key[3][3] ^= key[3][2];
}

/**
 * Copies all the values from arr2 into arr1. Used to keep a copy of
 * the original plaintext and key.
 */
void copy_data(unsigned char arr1[4][4], unsigned char arr2[4][4]) {
  // copy 1st row
  arr1[0][0] = arr2[0][0];
  arr1[0][1] = arr2[0][1];
  arr1[0][2] = arr2[0][2];
  arr1[0][3] = arr2[0][3];

  // copy 2nd row
  arr1[1][0] = arr2[1][0];
  arr1[1][1] = arr2[1][1];
  arr1[1][2] = arr2[1][2];
  arr1[1][3] = arr2[1][3];

  // copy 3rd row
  arr1[2][0] = arr2[2][0];
  arr1[2][1] = arr2[2][1];
  arr1[2][2] = arr2[2][2];
  arr1[2][3] = arr2[2][3];

  // copy 4th row
  arr1[3][0] = arr2[3][0];
  arr1[3][1] = arr2[3][1];
  arr1[3][2] = arr2[3][2];
  arr1[3][3] = arr2[3][3];
}

/**
 * Pretty prints a matrix to stdout.
 */
void print_matrix(unsigned char arr[4][4]) {
  printf("%02hhx %02hhx %02hhx %02hhx\n%02hhx %02hhx %02hhx %02hhx\n"
    "%02hhx %02hhx %02hhx %02hhx\n%02hhx %02hhx %02hhx %02hhx\n",
    arr[0][0], arr[0][1], arr[0][2], arr[0][3],
    arr[1][0], arr[1][1], arr[1][2], arr[1][3],
    arr[2][0], arr[2][1], arr[2][2], arr[2][3],
    arr[3][0], arr[3][1], arr[3][2], arr[3][3]);
}

int main(int argc, char** argv) {
  // struct timeval stop, start;
  int num_iterations, num_rounds, i, j;
  FILE *fp;
  unsigned char key[4][4], inputKey[4][4], text[4][4], plaintext[4][4];

  // read parameters from file "aesinput.txt"
  fp = fopen("aesinput.txt", "r");
  if (fp == NULL) {
    fprintf(stderr, "Cannot read file %s\n", "aesinput.txt");
    exit(1);
  }

  // load input file into parameters
  fscanf(fp, "%d\n", &num_iterations);
  fscanf(fp, "%d\n", &num_rounds);
  fscanf(fp, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx"
    "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx\n",
    &key[0][0], &key[1][0], &key[2][0], &key[3][0],
    &key[0][1], &key[1][1], &key[2][1], &key[3][1],
    &key[0][2], &key[1][2], &key[2][2], &key[3][2],
    &key[0][3], &key[1][3], &key[2][3], &key[3][3]);
  fscanf(fp, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx"
    "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx\n",
    &text[0][0], &text[1][0], &text[2][0], &text[3][0],
    &text[0][1], &text[1][1], &text[2][1], &text[3][1],
    &text[0][2], &text[1][2], &text[2][2], &text[3][2],
    &text[0][3], &text[1][3], &text[2][3], &text[3][3]);
  fclose(fp);

  // save backup of plaintext
  copy_data(plaintext, text);

  // printf("# iterations = %d\n", num_iterations);
  // printf("# rounds = %d\n", num_rounds);
  // printf("Key:\n");
  // printf("%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
  //     "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
  //     key[0][0], key[1][0], key[2][0], key[3][0],
  //     key[0][1], key[1][1], key[2][1], key[3][1],
  //     key[0][2], key[1][2], key[2][2], key[3][2],
  //     key[0][3], key[1][3], key[2][3], key[3][3]);
  // printf("Plaintext:\n");
  // printf("%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
  //     "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
  //     text[0][0], text[1][0], text[2][0], text[3][0],
  //     text[0][1], text[1][1], text[2][1], text[3][1],
  //     text[0][2], text[1][2], text[2][2], text[3][2],
  //     text[0][3], text[1][3], text[2][3], text[3][3]);

  // gettimeofday(&start, NULL);
  // printf("******* BEGIN ENCRYPTION *******\n");

  for (j = 0; j < num_iterations; j++) {
    // printf("***** ITERATION %d *****\n", j + 1);

    // In CBC, the previous ciphertext XOR plaintext is the input block
    if (j) {
      // printf("XOR of previous ciphertext with plaintext:\n");
      // print_matrix(plaintext);
      addRoundKey(text, plaintext);
      // print_matrix(text);
    }

    // printf("Input block:\n");
    // print_matrix(text);

    // update inputKey with original key and reset rcon to initial value
    copy_data(inputKey, key);
    rcon_i = 0;

    // printf("* Initial addRoundKey *\n");
    addRoundKey(text, inputKey);
    // print_matrix(text);

    for (i = 1; i < num_rounds; i++) {
      // printf("*** Round %d ***\n", i);

      // printf("* Round %d SubBytes and ShiftRows *\n", i);
      byteSub(text);
      // print_matrix(text);

      // printf("* Round %d MixColumns *\n", i);
      mixColumn(text);
      // print_matrix(text);

      // printf("** Round %d RoundKey **\n", i);
      nextRoundKey(inputKey);
      // print_matrix(inputKey);

      // printf("* Round %d AddRoundKey *\n", i);
      addRoundKey(text, inputKey);
      // print_matrix(text);
    }

    // printf("*** Round %d ***\n", num_rounds);

    // printf("* Round %d SubBytes and ShiftRows *\n", num_rounds);
    byteSub(text);
    // print_matrix(text);

    // printf("- No MixColumns in final round -\n");

    // printf("** Round %d RoundKey **\n", num_rounds);
    nextRoundKey(inputKey);
    // print_matrix(inputKey);

    // printf("* Round %d AddRoundKey *\n", num_rounds);
    addRoundKey(text, inputKey);
    // print_matrix(text);

    // printf("** Ciphertext block: **\n");
    // printf("%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
    //   "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
    //   text[0][0], text[1][0], text[2][0], text[3][0],
    //   text[0][1], text[1][1], text[2][1], text[3][1],
    //   text[0][2], text[1][2], text[2][2], text[3][2],
    //   text[0][3], text[1][3], text[2][3], text[3][3]);
  }
  // gettimeofday(&stop, NULL);
  // printf("*******  END ENCRYPTION  *******\n");
  printf("Final block:\n");
    printf("%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
      "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
      text[0][0], text[1][0], text[2][0], text[3][0],
      text[0][1], text[1][1], text[2][1], text[3][1],
      text[0][2], text[1][2], text[2][2], text[3][2],
      text[0][3], text[1][3], text[2][3], text[3][3]);

  // printf("Time duration: %.5f s\n",
  //   ((double) stop.tv_sec + 1.0e-6 * stop.tv_usec) -
  //   ((double) start.tv_sec + 1.0e-6 * start.tv_usec));

  return 0;
}
