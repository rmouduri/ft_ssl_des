#include <unistd.h>
#include <string.h>

#include "ft_ssl.h"


void print_usage(void) {
    write(STDERR_FILENO, FT_SSL_USAGE, ft_strlen(FT_SSL_USAGE));
}

void print_command_error(const char *command) {
    write(STDERR_FILENO, FT_SSL_INVALID_COMMAND_1, ft_strlen(FT_SSL_INVALID_COMMAND_1));
    write(STDERR_FILENO, command, ft_strlen(command));
    write(STDERR_FILENO, FT_SSL_INVALID_COMMAND_2, ft_strlen(FT_SSL_INVALID_COMMAND_2));
}

void print_malloc_error(const char *function) {
    write(STDERR_FILENO, "Malloc error in function: ", ft_strlen("Malloc error in function: "));
    write(STDERR_FILENO, function, ft_strlen(function));
    write(STDERR_FILENO, "\n", 1);
}

void print_read_error(const char *function) {
    write(STDERR_FILENO, "Read error in function: ", ft_strlen("Read error in function: "));
    write(STDERR_FILENO, function, ft_strlen(function));
    write(STDERR_FILENO, "\n", 1);
}

void print_encode_decode_error(void) {
    write(STDERR_FILENO, FT_SSL_BASE64_ENCODE_DECODE_ERROR, ft_strlen(FT_SSL_BASE64_ENCODE_DECODE_ERROR));
}

void print_hex_string_too_short(void) {
    write(STDERR_FILENO, FT_SSL_DES_HEX_STRING_TOO_SHORT, ft_strlen(FT_SSL_DES_HEX_STRING_TOO_SHORT));
}

void print_hex_string_too_long(void) {
    write(STDERR_FILENO, FT_SSL_DES_HEX_STRING_TOO_LONG, ft_strlen(FT_SSL_DES_HEX_STRING_TOO_LONG));
}