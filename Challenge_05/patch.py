from argparse import ArgumentParser
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *

parser = ArgumentParser()
parser.add_argument("original")
parser.add_argument("patched")
args = parser.parse_args()

backend = DetourBackend(args.original, replace_note_segment=True)
patches = []

# regenerate cfg with specified main function address
backend.cfg = backend.project.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False, function_starts={0x11169, })
backend.ordered_nodes = backend._get_ordered_nodes(backend.cfg)

################################################################
#  - Patch encrypt(0x1254C) and decrypt(0x125B8)
#     12c12
#     < #include "EVP_des_ede3_cbc.h"
#     ---
#     > #include "EVP_aes_256_cbc.h"
################################################################

EVP_aes_256_cbc_addr = hex(0x47f90)

# 0x12564: "bl EVP_des_ede3_cbc" in encrypt()
patches.append(InlinePatch(0x12564, "bl " + EVP_aes_256_cbc_addr))
# 0x125D0: "bl EVP_des_ede3_cbc" in decrypt()
patches.append(InlinePatch(0x125D0, "bl " + EVP_aes_256_cbc_addr))


################################################################
#  - Extend KEY and IV (by creating new variables)
#  - Patch logging_setup(0x12360) and write_encrypted(0x123CC)
#     28,30c28,30
#     < #define KEY_SIZE 24
#     < #define IV_SIZE 8
#     < #define EXTRA_ENC_BUFF 8
#     ---
#     > #define KEY_SIZE 32
#     > #define IV_SIZE 16
#     > #define EXTRA_ENC_BUFF 16
################################################################

# Creating new variables
patches.append(AddRWDataPatch(32, name="KEY"))
patches.append(AddRWDataPatch(16, name="IV"))

# replace logging_setup(0x12360) and write_encrypted(0x123CC)
header = '''
#include <linux/can.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>

#define BUFFER_SIZE 2
#define KEY_SIZE 32
#define IV_SIZE 16
#define EXTRA_ENC_BUFF 16

struct MBlock{
    char generation[4];
    struct can_frame frames[BUFFER_SIZE];
    struct timeval time_stamps[BUFFER_SIZE];
    uint32_t rx_counts[3];
    uint8_t can_rx_err_counts[3];
    uint8_t can_tx_err_counts[3];
    char version[3];
    char logger_number[2];
    char file_number[3];
    char micro_of_sdcard[3];
    uint32_t crc32;
};

extern unsigned char KEY[KEY_SIZE];
extern unsigned char IV[IV_SIZE];
'''

logging_setup = '''
extern FILE * wfd;
 FILE *fopen(const char *, const char *);
 void perror(const char *);
 void *memset(void *, int, size_t);
 void initialize_write(unsigned char *, int);
extern struct MBlock mblock;

void logging_setup(char * log_name){
    char wb[3];
    wb[0] = 'w'; wb[1] = 'b'; wb[2] = 0;
    char perror_str[43];
    perror_str[0] = 'C'; perror_str[1] = 'o'; perror_str[2] = 'u'; perror_str[3] = 'l'; perror_str[4] = 'd'; perror_str[5] = ' '; perror_str[6] = 'n'; perror_str[7] = 'o'; perror_str[8] = 't'; perror_str[9] = ' '; perror_str[10] = 'c'; perror_str[11] = 'r'; perror_str[12] = 'e'; perror_str[13] = 'a'; perror_str[14] = 't'; perror_str[15] = 'e'; perror_str[16] = ' '; perror_str[17] = 'i'; perror_str[18] = 'n'; perror_str[19] = 'i'; perror_str[20] = 't'; perror_str[21] = 'i'; perror_str[22] = 'a'; perror_str[23] = 'l'; perror_str[24] = ' '; perror_str[25] = 'd'; perror_str[26] = 'e'; perror_str[27] = 's'; perror_str[28] = 'c'; perror_str[29] = 'r'; perror_str[30] = 'i'; perror_str[31] = 'p'; perror_str[32] = 't'; perror_str[33] = 'o'; perror_str[34] = 'r'; perror_str[35] = ' '; perror_str[36] = 'f'; perror_str[37] = 'o'; perror_str[38] = 'r'; perror_str[39] = ' '; perror_str[40] = '%'; perror_str[41] = 's'; perror_str[42] = 0;

    /* Open File Descriptor */
     if ((wfd = fopen(log_name, wb)) == NULL)
            perror(perror_str);
    /* Initialize the tally counts */
    memset(mblock.rx_counts, 0, sizeof (mblock.rx_counts));
    memset(mblock.can_rx_err_counts, 0, sizeof (mblock.can_rx_err_counts));
    memset(mblock.can_tx_err_counts, 0, sizeof (mblock.can_tx_err_counts));
    /* Setup and write Key and IV */
    initialize_write(KEY, KEY_SIZE);
    initialize_write(IV, IV_SIZE);
}
'''

write_encrypted = '''
 void *malloc(size_t);
 void *memcpy(void *, const void *, size_t);
extern struct MBlock mblock;
extern FILE * wfd;
 size_t fwrite(const void *, size_t, size_t, FILE *);
 void perror(const char *);
 void free(void *);
 void initialize_write(unsigned char *, int);
 int encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);

void write_encrypted() {
    char perror_str0[27];
    perror_str0[0] = 'C'; perror_str0[1] = 'o'; perror_str0[2] = 'u'; perror_str0[3] = 'l'; perror_str0[4] = 'd'; perror_str0[5] = ' '; perror_str0[6] = 'n'; perror_str0[7] = 'o'; perror_str0[8] = 't'; perror_str0[9] = ' '; perror_str0[10] = 'w'; perror_str0[11] = 'r'; perror_str0[12] = 'i'; perror_str0[13] = 't'; perror_str0[14] = 'e'; perror_str0[15] = ' '; perror_str0[16] = 't'; perror_str0[17] = 'a'; perror_str0[18] = 'g'; perror_str0[19] = ' '; perror_str0[20] = 'l'; perror_str0[21] = 'e'; perror_str0[22] = 'n'; perror_str0[23] = 'g'; perror_str0[24] = 't'; perror_str0[25] = 'h'; perror_str0[26] = 0;
    char perror_str1[37];
    perror_str1[0] = 'C'; perror_str1[1] = 'o'; perror_str1[2] = 'u'; perror_str1[3] = 'l'; perror_str1[4] = 'd'; perror_str1[5] = ' '; perror_str1[6] = 'n'; perror_str1[7] = 'o'; perror_str1[8] = 't'; perror_str1[9] = ' '; perror_str1[10] = 'w'; perror_str1[11] = 'r'; perror_str1[12] = 'i'; perror_str1[13] = 't'; perror_str1[14] = 'e'; perror_str1[15] = ' '; perror_str1[16] = 'c'; perror_str1[17] = 'i'; perror_str1[18] = 'p'; perror_str1[19] = 'h'; perror_str1[20] = 'e'; perror_str1[21] = 'r'; perror_str1[22] = 't'; perror_str1[23] = 'e'; perror_str1[24] = 'x'; perror_str1[25] = 't'; perror_str1[26] = ' '; perror_str1[27] = 'o'; perror_str1[28] = 'f'; perror_str1[29] = ' '; perror_str1[30] = 'l'; perror_str1[31] = 'e'; perror_str1[32] = 'n'; perror_str1[33] = 'g'; perror_str1[34] = 't'; perror_str1[35] = 'h'; perror_str1[36] = 0;

    int bytes_written = 0;
    /* Allocate plaintext buffer, and fill with Mblock data */
    unsigned char *plaintext = (unsigned char *)malloc(sizeof(mblock));
    memcpy(plaintext, &mblock, sizeof(mblock));
    /* Allocate buffer for returning ciphertext, plus some extra bytes */
    unsigned char *ciphertext = (unsigned char *)malloc(sizeof(mblock) + EXTRA_ENC_BUFF);
    /* Pass plaintext to encryption algorithm */
    bytes_written = encrypt(plaintext, sizeof(mblock), KEY, IV, ciphertext);
    /* Write Mblock Length:Mblock */
    if (fwrite(&bytes_written, sizeof(int), 1, wfd) < 1) {
        perror(perror_str0);
    }
    if (fwrite(ciphertext, 1, bytes_written, wfd) < 1) {
        perror(perror_str1);
    }
    free(plaintext);
    free(ciphertext);
    initialize_write(IV, IV_SIZE);
}
'''

logging_setup_symbols = {"wfd": 0x1BE494,
                         "mblock": 0x1BC5A8,
                         "fopen": 0xF40F5,
                         "perror": 0xF36B9,
                         "initialize_write": 0x122F9,
                         }

write_encrypted_symbols = {"wfd": 0x1BE494,
                           "mblock": 0x1BC5A8,
                           "malloc": 0xFE05D,
                           "memcpy": 0x10184,
                           "fwrite": 0xF4481,
                           "perror": 0xF36B9,
                           "free": 0xFE4E5,
                           "initialize_write": 0x122F9,
                           "encrypt": 0x1254D,
                           }

patches.append(ReplaceFunctionPatch(0x12360, 0x6C, header + logging_setup, symbols=logging_setup_symbols))
patches.append(ReplaceFunctionPatch(0x123CC, 0xA8, header + write_encrypted, symbols=write_encrypted_symbols))

backend.apply_patches(patches)
backend.save(args.patched)
