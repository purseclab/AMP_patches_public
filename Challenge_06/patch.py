from argparse import ArgumentParser
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
import logging

# parse command line arguments
parser = ArgumentParser()
parser.add_argument("original")
parser.add_argument("patched")
parser.add_argument("patchinfo", nargs="?")
args = parser.parse_args()

# setup logging options
logging.getLogger("angr").propagate = False
logging.getLogger("cle").propagate = False
logging.getLogger("pyvex").propagate = False
logging.getLogger("patcherex").setLevel(logging.DEBUG)

# initialize backend
backend = DetourBackend(args.original, replace_note_segment=True, try_reuse_unused_space=True)
patches = []

# replace the original hash function (using CRC-32) with a modified version of it (using SHA-256)
digest_message = '''
#include <stdlib.h>
typedef void EVP_MD_CTX;
void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_free(mdctx);
}
'''

digest_message_symbols = {"EVP_MD_CTX_new": 0x4CCA9,
                          "EVP_DigestInit_ex": 0x4CCD5,
                          "EVP_DigestUpdate": 0x4CE5D,
                          "EVP_DigestFinal_ex": 0x4CE69,
                          "EVP_MD_CTX_free": 0x4CCB9,
                          "OPENSSL_malloc": 0x1BE55,
                          "handleErrors": 0x1274D,
                          "EVP_sha256": 0x51BE9,
                          "EVP_MD_size": 0x18A6D,
                          }

patches.append(ReplaceFunctionPatch(
    0x126D2, 0x7A, digest_message, symbols=digest_message_symbols))


# replace the CRC-32 call with a SHA-256 call in write_encrypted() and update INTEGRITY_SIZE in reset_mblock(), logging_setup(), and serialize()
# write_encrypted at 0x123A8, reset_mblock at 0x12290, logging_setup at 0x122D4, serialize at 0x12500

header = '''
#include <linux/can.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>

#define BUFFER_SIZE 2

#define INTEGRITY_SIZE 32
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
    unsigned char *integrity_ptr;
};

extern unsigned char KEY[KEY_SIZE];
extern unsigned char IV[IV_SIZE];
extern FILE * wfd;
extern struct MBlock mblock;
'''

write_encrypted = '''
extern unsigned char * serialize(uint32_t *);
extern int encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);
extern void digest_message(const unsigned char *, size_t, unsigned char **, unsigned int *);
extern char * perror_str_0;
extern char * perror_str_1;
void write_encrypted(void) {
    unsigned char *buffer;
    unsigned int digest_length;
    unsigned char *plaintext;

    unsigned char *mblock_data;
    int bytes_written = 0;
    uint32_t mblock_size = 0;
    unsigned char *ciphertext;

    mblock_data = serialize(&mblock_size);
    buffer = malloc (mblock_size);
    digest_message(mblock_data, mblock_size - INTEGRITY_SIZE, &buffer, &digest_length);
    if (digest_length != INTEGRITY_SIZE) {
        handleErrors();
    }
    memcpy(mblock.integrity_ptr, buffer, digest_length);
    free(buffer);

    free(mblock_data);
    plaintext = serialize(&mblock_size);
    ciphertext = malloc(mblock_size + EXTRA_ENC_BUFF);
    bytes_written = encrypt(plaintext, mblock_size, KEY, IV, ciphertext);
    if (fwrite(&bytes_written, sizeof(int), 1, wfd) < 1) {
        perror(&perror_str_0);
    }
    if (fwrite(ciphertext, 1, bytes_written, wfd) < 1) {
        perror(&perror_str_1);
    }
    free(plaintext);
    free(ciphertext);
    initialize_write(IV, IV_SIZE);
}
'''

reset_mblock = '''
extern void *memset_(void *, int, size_t);
void __attribute__((optimize("O0"))) reset_mblock(){
    memset_(mblock.frames, 0, BUFFER_SIZE*sizeof(struct can_frame));
    memset_(mblock.time_stamps, 0, BUFFER_SIZE*sizeof(struct timeval));
    memset_(mblock.integrity_ptr, 0, INTEGRITY_SIZE);
}
'''

logging_setup = '''
extern char * wb;
extern char * perror_str_0;
void logging_setup(char * log_name){
     if ((wfd = fopen(log_name, &wb)) == NULL)
            perror(&perror_str_0);
    memset(mblock.rx_counts, 0, sizeof (mblock.rx_counts));
    memset(mblock.can_rx_err_counts, 0, sizeof (mblock.can_rx_err_counts));
    memset(mblock.can_tx_err_counts, 0, sizeof (mblock.can_tx_err_counts));
    mblock.integrity_ptr = malloc(INTEGRITY_SIZE);
    initialize_write(KEY, KEY_SIZE);
    initialize_write(IV, IV_SIZE);
}
'''

serialize = '''
unsigned char* __attribute__((optimize("O0"))) serialize(uint32_t* mblock_size) {
    uint32_t tmp_size = 0;
    tmp_size = tmp_size + sizeof(mblock.generation) + sizeof(mblock.frames) + sizeof(mblock.time_stamps)
     + sizeof(mblock.rx_counts) + sizeof(mblock.can_rx_err_counts) + sizeof(mblock.can_tx_err_counts)
     + sizeof(mblock.version) + sizeof(mblock.logger_number) + sizeof(mblock.file_number)
     + sizeof(mblock.micro_of_sdcard) + INTEGRITY_SIZE;

    unsigned char *data = malloc(tmp_size);
    *mblock_size = tmp_size;
    uint32_t c_size = 0;

    memcpy(data + c_size, mblock.generation, sizeof(mblock.generation));
    c_size = c_size + sizeof(mblock.generation);

    memcpy(data + c_size, mblock.frames, sizeof(mblock.frames));
    c_size = c_size + sizeof(mblock.frames);

    memcpy(data + c_size, mblock.time_stamps, sizeof(mblock.time_stamps));
    c_size = c_size + sizeof(mblock.time_stamps);

    memcpy(data + c_size, mblock.rx_counts, sizeof(mblock.rx_counts));
    c_size = c_size + sizeof(mblock.rx_counts);

    memcpy(data + c_size, mblock.can_rx_err_counts, sizeof(mblock.can_rx_err_counts));
    c_size = c_size + sizeof(mblock.can_rx_err_counts);

    memcpy(data + c_size, mblock.can_tx_err_counts, sizeof(mblock.can_tx_err_counts));
    c_size = c_size + sizeof(mblock.can_tx_err_counts);

    memcpy(data + c_size, mblock.version, sizeof(mblock.version));
    c_size = c_size + sizeof(mblock.version);

    memcpy(data + c_size, mblock.logger_number, sizeof(mblock.logger_number));
    c_size = c_size + sizeof(mblock.logger_number);

    memcpy(data + c_size, mblock.file_number, sizeof(mblock.file_number));
    c_size = c_size + sizeof(mblock.file_number);

    memcpy(data + c_size, mblock.micro_of_sdcard, sizeof(mblock.micro_of_sdcard));
    c_size = c_size + sizeof(mblock.micro_of_sdcard);

    void * (*memcpy_ptr)(void *, const void *, size_t) = &memcpy; 
    (*memcpy_ptr)(data + c_size, mblock.integrity_ptr, INTEGRITY_SIZE);
    return data;
}
'''

write_encrypted_symbols = {"serialize": 0x12501,
                           "malloc": 0xFD81D,
                           "digest_message": 0x126D3,
                           "handleErrors": 0x1274D,
                           "memcpy": 0x10184,
                           "free": 0xFDCA5,
                           "encrypt": 0x12769,
                           "fwrite": 0xF3C41,
                           "perror": 0xF2E79,
                           "initialize_write": 0x12341,
                           "mblock": 0x1BB5A8,
                           "KEY": 0x1BD094,
                           "IV": 0x1BD0B4,
                           "wfd": 0x1BD0C4,
                           "perror_str_0": 0x13F9DC,
                           "perror_str_1": 0x13F9F8,
                           }

reset_mblock_symbols = {"memset_": 0x1002F0,
                        "mblock": 0x1BB5A8,
                        }

logging_setup_symbols = {"fopen": 0xF38B5,
                         "perror": 0xF2E79,
                         "memset": 0x1002F0,
                         "malloc": 0xFD81D,
                         "initialize_write": 0x12341,
                         "mblock": 0x1BB5A8,
                         "KEY": 0x1BD094,
                         "IV": 0x1BD0B4,
                         "wfd": 0x1BD0C4,
                         "wb": 0x13F958,
                         "perror_str_0": 0x13F95C,
                         }

serialize_symbols = {"malloc": 0xFD81D,
                     "memcpy": 0x10184,
                     "mblock": 0x1BB5A8,
                     }

patches.append(ReplaceFunctionPatch(0x123A8, 0xC4, header +
               write_encrypted, symbols=write_encrypted_symbols))
patches.append(ReplaceFunctionPatch(0x12290, 0x44, header +
               reset_mblock, symbols=reset_mblock_symbols))
patches.append(ReplaceFunctionPatch(0x122D4, 0x6C, header +
               logging_setup, symbols=logging_setup_symbols))
patches.append(ReplaceFunctionPatch(0x12500, 0x17C, header +
               serialize, symbols=serialize_symbols))

# apply all the patches to the original binary
backend.apply_patches(patches)

# save the patched binary to a file
backend.save(args.patched)

# export the patch info to a file
if args.patchinfo:
    backend.export_patch_info(args.patchinfo)
