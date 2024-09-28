#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include "ft_ssl.h"
#include "display.h"

void ft_hexdump(const void *ptr, int size, int fd) {
    const unsigned char *buffer = (unsigned char *) ptr;
    int i, j;

    for (i = 0; i < size; i += 16) {
        ft_dprintf(fd, "%08x  ", i);

        for (j = 0; j < 16; j++) {
            if (j == 8) ft_dprintf(fd, " ");
            if (i + j < size) {
                ft_dprintf(fd, "%02x ", buffer[i + j]);
            } else {
                ft_dprintf(fd, "   ");
            }
        }

        ft_dprintf(fd, " |");

        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                const unsigned char ch = buffer[i + j];
                if (isprint(ch)) {
                    ft_dprintf(fd, "%c", ch);
                } else {
                    ft_dprintf(fd, ".");
                }
            }
        }

        ft_dprintf(fd, "|\n");
    }
}

void ft_binarydump(const void *ptr, int size, int fd) {
    const unsigned char *buffer = (unsigned char *) ptr;
    int i, j;

    for (i = 0; i < size; i += 8) {
        ft_dprintf(fd, "%08x  ", i);

        for (j = 0; j < 8; j++) {
            if (i + j < size) {
                const unsigned char byte = buffer[i + j];
                for (int bit = 7; bit >= 0; bit--) {
                    ft_dprintf(fd, "%d", (byte >> bit) & 1);
                }
                ft_dprintf(fd, " ");
            } else {
                ft_dprintf(fd, "         ");
            }
        }

        ft_dprintf(fd, " ");

        for (j = 0; j < 8; j++) {
            if (i + j < size) {
                const unsigned char ch = buffer[i + j];
                if (isprint(ch)) {
                    ft_dprintf(fd, "%c", ch);
                } else {
                    ft_dprintf(fd, ".");
                }
            }
        }

        ft_dprintf(fd, "\n");
    }
}

static void display_hash(const uint8_t *hash, ssl_encrypt_algo_t algo, int fd) {
    uint64_t size;

    if (algo == MD5) {
        size = 128;
    } else if (algo == SHA256) {
        size = 256;
    }

    for (uint64_t i = 0; i < (size / 8); ++i) {
        ft_dprintf(fd, "%02x", hash[i]);
    }
}

static void print_no_esc_char(uint8_t *input, int fd) {
    while (*input) {
        if (isprint(*input)) {
            ft_dprintf(fd, "%c", *input);
        }

        ++input;
    }
}

static void display_arg_input(const ssl_input_t *input, ssl_encrypt_algo_t algo, ssl_option_t options, int fd) {
    const char algo_strings[6][16] = ALGO_STRING;

    if (!(options & QUIET_MODE_OPTION) && !(options & REVERSE_MODE_OPTION)) {
        ft_dprintf(fd, "%s (\"", algo_strings[algo]);
        print_no_esc_char(input->ssl_str, fd);
        ft_dprintf(fd, "\") = ");
    }

    display_hash(input->hash, algo, fd);

    if (!(options & QUIET_MODE_OPTION) && options & REVERSE_MODE_OPTION) {
        ft_dprintf(fd, " \"");
        print_no_esc_char(input->ssl_str, fd);
        ft_dprintf(fd, "\"");
    }

    ft_dprintf(fd, "\n");
}

static void display_file_input(const ssl_input_t *input, ssl_encrypt_algo_t algo, ssl_option_t options, int fd) {
    const char algo_strings[6][16] = ALGO_STRING;

    if (!(options & QUIET_MODE_OPTION) && !(options & REVERSE_MODE_OPTION)) {
        ft_dprintf(fd, "%s (", algo_strings[algo]);
        print_no_esc_char((uint8_t *) input->ssl_arg, fd);
        ft_dprintf(fd, ") = ");
    }

    display_hash(input->hash, algo, fd);

    if (!(options & QUIET_MODE_OPTION) && options & REVERSE_MODE_OPTION) {
        ft_dprintf(fd, " ");
        print_no_esc_char((uint8_t *) input->ssl_arg, fd);
    }

    ft_dprintf(fd, "\n");
}

static void display_stdin_input(const ssl_input_t *input, ssl_encrypt_algo_t algo, ssl_option_t options, int fd) {
    if (!(options & QUIET_MODE_OPTION)) {
        if (options & ECHO_STDIN_OPTION) {
            ft_dprintf(fd, "(\"");
            print_no_esc_char(input->ssl_str, fd);
            ft_dprintf(fd, "\")= ");
        } else {
            ft_dprintf(fd, "(stdin)= ");
        }
    } else if (options & ECHO_STDIN_OPTION) {
        print_no_esc_char(input->ssl_str, fd);
        ft_dprintf(fd, "\n");
    }

    display_hash(input->hash, algo, fd);
    ft_dprintf(fd, "\n");
}

void display_md5_sha256(const ssl_input_t *input, ssl_encrypt_algo_t algo, ssl_option_t options, int fd) {
    if (input->type == FILE_INPUT && input->ssl_str == NULL && input->len == 1) {
        ft_dprintf(fd, SSL_NO_FILE_DIRECTORY, input->ssl_arg);
        return ;
    }

    if (input->type == ARG_INPUT) {
        display_arg_input(input, algo, options, fd);
    } else if (input->type == FILE_INPUT) {
        display_file_input(input, algo, options, fd);
    } else if (input->type == STDIN_INPUT) {
        display_stdin_input(input, algo, options, fd);
    }
}

void display_base64(int fd, const uint8_t *s, uint64_t len, bool decode) {
    if (decode) {
        for (uint64_t i = 0; i < len; ++i) {
            write(fd, s + i, 1);
        }
    } else {
        for (uint64_t i = 0; i < len; i += 64) {
            ft_dprintf(fd, "%.64s\n", s + i);
        }
    }

}