#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef _FT_SSL_
# define _FT_SSL_

# include "ft_dprintf.h"

# define FT_SSL     "ft_ssl"

# define MD5_COMMAND_ARG        "md5"
# define SHA256_COMMAND_ARG     "sha256"
# define BASE64_COMMAND_ARG      "base64"
# define DES_COMMAND_ARG        "des"
# define DES_ECB_COMMAND_ARG    "des-ecb"
# define DES_CBC_COMMAND_ARG    "des-cbc"

# define HELP_ARG           "-h"

/* md5 | sha256 */
# define ECHO_STDIN_ARG     "-p"
# define QUIET_MODE_ARG     "-q"
# define REVERSE_MODE_ARG   "-r"
# define STRING_ARG         "-s"

/* base64 */
# define DECODE_MODE_ARG    "-d"
# define ENCODE_MODE_ARG    "-e"
# define INPUT_FILE_ARG     "-i"
# define OUTPUT_FILE_ARG    "-o"

/* des | des-ecb | des-cbc */
# define DE_ENCODE_IN_OUTPUT_BASE64_ARG "-a"
# define DECRYPT_MODE_ARG               "-d"
# define ENCRYPT_MODE_ARG               "-e"
# define INPUT_MESSAGE_FILE_ARG         "-i"
# define KEY_HEX_ARG                    "-k"
# define OUTPUT_MESSAGE_FILE_ARG        "-o"
# define PASSWORD_ASCII_ARG             "-p"
# define SALT_HEX_ARG                   "-s"
# define INIT_VECTOR_HEX_ARG            "-v"
# define DISPLAY_KEY_IV_ARG             "-P"


# define FT_SSL_USAGE   "usage: "FT_SSL" command [flags] [FILE_INPUT/string]\n"
# define FT_SSL_INVALID_COMMAND_1   FT_SSL": Error: '"
# define FT_SSL_INVALID_COMMAND_2   "' is an invalid command.\n\n"
# define FT_SSL_HELP    "Standard commands:\n" \
                        MD5_COMMAND_ARG"\n" \
                        SHA256_COMMAND_ARG"\n\n" \
                        "Cipher commands:\n" \
                        BASE64_COMMAND_ARG"\n" \
                        DES_COMMAND_ARG"\n" \
                        DES_CBC_COMMAND_ARG"\n" \
                        DES_ECB_COMMAND_ARG"\n"
# define FT_SSL_BASE64_ENCODE_DECODE_ERROR  "Please choose between encode (-e) or decode (-d).\n"
# define FT_SSL_DES_HEX_STRING_TOO_SHORT  "hex string is too short, padding with zero bytes to length\n"
# define FT_SSL_DES_HEX_STRING_TOO_LONG  "hex string is too long, ignoring excess\n"


# define ALGO_STRING { \
    "MD5", \
    "SHA256", \
    "BASE64", \
    "DES", \
    "DES-ECB", \
    "DES-CBC" \
}

typedef enum ssl_encrypt_algo_s {
    MD5,
    SHA256,
    BASE64,
    DES,
    DES_ECB,
    DES_CBC
} ssl_encrypt_algo_t;

typedef enum ssl_md5_sha256_option_e {
    ECHO_STDIN_OPTION   = 1 << 0,
    QUIET_MODE_OPTION   = 1 << 1,
    REVERSE_MODE_OPTION = 1 << 2
} ssl_md5_sha256_option_t;

typedef enum ssl_base64_option_e {
    DECODE_MODE_OPTION  = 1 << 0,
    ENCODE_MODE_OPTION  = 1 << 1
} ssl_base64_option_t;

typedef enum ssl_des_option_e {
    DE_ENCODE_IN_OUTPUT_BASE64_OPTION   = 1 << 0,
    DECRYPT_MODE_OPTION                 = 1 << 1,
    ENCRYPT_MODE_OPTION                 = 1 << 2,
    DISPLAY_KEY_IV_SALT_OPTION          = 1 << 3
} ssl_des_option_t;

typedef enum ssl_input_type_e {
    STDIN_INPUT,
    ARG_INPUT,
    FILE_INPUT
} ssl_input_type_t;

typedef struct ssl_input_s {
    uint8_t             *hash;
    uint8_t             *ssl_str;
    const char          *ssl_arg;
    uint64_t            len;
    ssl_input_type_t    type;
    ssl_encrypt_algo_t  encrypt_algo;
    struct ssl_input_s  *next;
} ssl_input_t;

typedef int ssl_option_t;

typedef struct ssl_s {
    ssl_encrypt_algo_t  algo;
    ssl_option_t        options;
    int                 fd;
    /* md5 && sha256 */
    ssl_input_t         *ssl_inputs;
    /* base64 && des */
    char                *message;
    uint64_t            message_len;
    /* des */
    char                *key;
    char                *password;
    char                *salt;
    char                *init_vector;
    uint8_t             *output;
    uint64_t            output_len;
} ssl_t;


/* option.c */
int check_args(int argc, char **argv, ssl_t *ssl);

/* error.c */
void print_usage(void);
void print_command_error(const char *command);
void print_malloc_error(const char *function);
void print_read_error(const char *function);
void print_encode_decode_error(void);
void print_hex_string_too_short(void);
void print_hex_string_too_long(void);

/* utils.c */
void    *ft_memcpy(void *dest, const void *src, size_t n);
int     ft_memcmp(const void *s1, const void *s2, size_t n);
void    *ft_memset(void *s, int c, size_t n);
int     ft_strcmp(const char *s1, const char *s2);
int     ft_strncmp(const char *s1, const char *s2, const size_t n);
void    free_ssl(ssl_t *ssl);

/* algorithms */
uint8_t *ft_md5(const uint8_t *input, const size_t input_len);
uint8_t *ft_sha256(const uint8_t *input, const size_t input_len);
char    *ft_base64(const char *input, const size_t input_len, ssl_base64_option_t options, size_t *output_len);
uint8_t *ft_des(ssl_t *ssl);

#endif // _FT_SSL_
