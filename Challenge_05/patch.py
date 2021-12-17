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
extern char * wb;
extern char * perror_str;

void logging_setup(char * log_name){
    /* Open File Descriptor */
     if ((wfd = fopen(log_name, &wb)) == NULL)
            perror(&perror_str);
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
extern char * perror_str0;
extern char * perror_str1;
 size_t fwrite(const void *, size_t, size_t, FILE *);
 void perror(const char *);
 void free(void *);
 void initialize_write(unsigned char *, int);
 int encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);

void write_encrypted() {
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
        perror(&perror_str0);
    }
    if (fwrite(ciphertext, 1, bytes_written, wfd) < 1) {
        perror(&perror_str1);
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
                         "wb": 0x1401B0,
                         "perror_str": 0x1401B4,
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
                           "perror_str0": 0x1401E0,
                           "perror_str1": 0x1401FC,
                           }

patches.append(ReplaceFunctionPatch(0x12360, 0x6C, header + logging_setup, symbols=logging_setup_symbols))
patches.append(ReplaceFunctionPatch(0x123CC, 0xA8, header + write_encrypted, symbols=write_encrypted_symbols))

backend.apply_patches(patches)
backend.save(args.patched)
