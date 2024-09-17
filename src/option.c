#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include "ft_ssl.h"

static int8_t read_fd(int fd, uint8_t **dest, uint64_t *len) {
    uint8_t buffer[256];
    uint8_t *tmp = NULL;
    int64_t r;

    *len = 0;
    while ((r = read(fd, buffer, 256)) > 0) {
        if (*len && (tmp = malloc(sizeof(uint8_t) * (*len))) == NULL) {
            if (*dest) { free(*dest); }
            *dest = NULL;
            return -1;
        }

        ft_memcpy(tmp, *dest, *len);

        if (*dest) { free(*dest); }
        if ((*dest = malloc(sizeof(uint8_t) * (*len + r))) == NULL) {
            if (tmp) { free(tmp); }
            return -1;
        }

        ft_memcpy(*dest, tmp, *len);
        ft_memcpy(*dest + *len, buffer, r);

        if (tmp) { free(tmp); }
        tmp = NULL;

        *len += r;
    }

    if (r == -1) {
        if (*dest) { free(*dest); }
        print_read_error("read_fd");
        return -1;
    }

    return 0;
}

static int add_entry(ssl_t *ssl, const char *input, ssl_input_type_t type) {
    ssl_input_t *tmp = ssl->ssl_inputs;
    ssl_input_t *new_entry;

    while (tmp && tmp->next) { tmp = tmp->next; }

    if ((new_entry = malloc(sizeof(ssl_input_t))) == NULL) {
        print_malloc_error("add_entry");
        return -1;
    }

    new_entry->ssl_str = NULL;

    new_entry->encrypt_algo = ssl->algo;
    new_entry->type = type;
    new_entry->ssl_arg = input;
    new_entry->hash = NULL;
    new_entry->next = NULL;

    if (type == ARG_INPUT) {
        new_entry->ssl_str = (uint8_t *) input;
        new_entry->len = ft_strlen((char *) new_entry->ssl_str);
    } else if (type == FILE_INPUT) {
        int fd;
        new_entry->len = 1;
        if ((fd = open(input, O_RDONLY)) != -1
                && read_fd(fd, &new_entry->ssl_str, &new_entry->len) == -1) {
            return -1;
        }
        close(fd);
    } else if (type == STDIN_INPUT) {
        if (read_fd(STDIN_FILENO, &new_entry->ssl_str, &new_entry->len) == -1) {
            free(new_entry);
            return -1;
        }

        new_entry->next = ssl->ssl_inputs;
        ssl->ssl_inputs = new_entry;
    }

    if (type != STDIN_INPUT) {
        if (tmp) {
            tmp->next = new_entry;
        } else {
            ssl->ssl_inputs = new_entry;
        }
    }

    return 0;
}

static void print_help(void) {
    write(STDOUT_FILENO, FT_SSL_HELP, ft_strlen(FT_SSL_HELP));
}

static int check_command(const char *command, ssl_t *ssl) {
    if (ft_strcmp(MD5_COMMAND_ARG, command) == 0) {
        ssl->algo = MD5;
    } else if (ft_strcmp(SHA256_COMMAND_ARG, command) == 0) {
        ssl->algo = SHA256;
    } else if (ft_strcmp(BASE64_COMMAND_ARG, command) == 0) {
        ssl->algo = BASE64;
    } else if (ft_strcmp(DES_COMMAND_ARG, command) == 0) {
        ssl->algo = DES;
    } else if (ft_strcmp(DES_ECB_COMMAND_ARG, command) == 0) {
        ssl->algo = DES_ECB;
    } else if (ft_strcmp(DES_CBC_COMMAND_ARG, command) == 0) {
        ssl->algo = DES_CBC;
    } else if (ft_strcmp(HELP_ARG, command) == 0) {
        print_help();
        return -1;
    } else {
        print_command_error(command);
        return -1;
    }

    return 0;
}

int check_md5_sha256_options(int argc, char **argv, ssl_t *ssl) {
    int i = 2;

    while (i < argc) {
        if (ft_strcmp(HELP_ARG, argv[i]) == 0) {
            print_help();
            free_ssl(ssl);
            return -1;
        } else if (ft_strcmp(ECHO_STDIN_ARG, argv[i]) == 0
                && !(ssl->options & ECHO_STDIN_OPTION)) {
            ssl->options |= ECHO_STDIN_OPTION;
            if (add_entry(ssl, NULL, STDIN_INPUT) == -1) {
                free_ssl(ssl);
                return -1;
            }
        } else if (ft_strcmp(QUIET_MODE_ARG, argv[i]) == 0) {
            ssl->options |= QUIET_MODE_OPTION;
        } else if (ft_strcmp(REVERSE_MODE_ARG, argv[i]) == 0) {
            ssl->options |= REVERSE_MODE_OPTION;
        } else if (ft_strcmp(STRING_ARG, argv[i]) == 0) {
            if (i + 1 >= argc) break;
            if (add_entry(ssl, argv[++i], ARG_INPUT) == -1) {
                free_ssl(ssl);
                return -1;
            }
        } else {
            break;
        }

        ++i;
    }

    while (i < argc) {
        if (add_entry(ssl, argv[i], FILE_INPUT) == -1) {
            free_ssl(ssl);
            return -1;
        }

        ++i;
    }

    if (ssl->ssl_inputs == NULL && add_entry(ssl, NULL, STDIN_INPUT) == -1) {
        return -1;
    }

    return 0;
}

int check_base64_options(int argc, char **argv, ssl_t *ssl) {
    int i = 2;

    while (i < argc) {
        if (ft_strcmp(HELP_ARG, argv[i]) == 0) {
            print_help();
            free_ssl(ssl);
            return -1;
        } else if (ft_strcmp(DECODE_MODE_ARG, argv[i]) == 0) {
            if (ssl->options & ENCODE_MODE_OPTION) {
                print_encode_decode_error();
                free_ssl(ssl);
                return -1;
            }
            ssl->options |= DECODE_MODE_OPTION;
        } else if (ft_strcmp(ENCODE_MODE_ARG, argv[i]) == 0) {
            if (ssl->options & DECODE_MODE_OPTION) {
                print_encode_decode_error();
                free_ssl(ssl);
                return -1;
            }
            ssl->options |= ENCODE_MODE_OPTION;
        } else if (ft_strcmp(INPUT_FILE_ARG, argv[i]) == 0) {
            int fd;
            if (i + 1 >= argc
                    || (fd = open(argv[++i], O_RDONLY)) == -1
                    || read_fd(fd, (uint8_t **)&ssl->message, &ssl->message_len) == -1) {
                free_ssl(ssl);
                return -1;
            }
            close(fd);
        } else if (ft_strcmp(OUTPUT_FILE_ARG, argv[i]) == 0) {
            if (i + 1 >= argc || (ssl->fd = open(argv[++i], O_WRONLY | O_CREAT, 0666)) == -1) {
                free_ssl(ssl);
                return -1;
            }
        } else {
            break;
        }

        ++i;
    }

    if (ssl->message == NULL
            && read_fd(STDIN_FILENO, (uint8_t **)&ssl->message, &ssl->message_len) == -1) {
        free_ssl(ssl);
        return -1;
    }

    return 0;
}

int check_des_options(int argc, char **argv, ssl_t *ssl) {
    int i = 2;

    while (i < argc) {
        if (ft_strcmp(HELP_ARG, argv[i]) == 0) {
            print_help();
            free_ssl(ssl);
            return -1;
        } else if (ft_strcmp(DE_ENCODE_IN_OUTPUT_BASE64_ARG, argv[i]) == 0) {
            ssl->options |= DE_ENCODE_IN_OUTPUT_BASE64_OPTION;
        } else if (ft_strcmp(DECRYPT_MODE_ARG, argv[i]) == 0) {
            ssl->options |= DECRYPT_MODE_OPTION;
        } else if (ft_strcmp(ENCRYPT_MODE_ARG, argv[i]) == 0) {
            ssl->options |= ENCRYPT_MODE_OPTION;
        } else if (ft_strcmp(INPUT_MESSAGE_FILE_ARG, argv[i]) == 0) {
            int fd;
            if (i + 1 >= argc
                    || (fd = open(argv[++i], O_RDONLY)) == -1
                    || read_fd(fd, (uint8_t **)&ssl->message, &ssl->message_len) == -1) {
                free_ssl(ssl);
                return -1;
            }
            close(fd);
        } else if (ft_strcmp(OUTPUT_FILE_ARG, argv[i]) == 0) {
            if (i + 1 >= argc || (ssl->fd = open(argv[++i], O_WRONLY | O_CREAT, 0666)) == -1) {
                free_ssl(ssl);
                return -1;
            }
        } else if (ft_strcmp(KEY_HEX_ARG, argv[i]) == 0) {
            if (i + 1 >= argc) {
                write(STDERR_FILENO, "Missing hex key argument.\n", ft_strlen("Missing hex key argument.\n")); 
                return -1;
            }
            ssl->key = argv[++i];
        } else if (ft_strcmp(PASSWORD_ASCII_ARG, argv[i]) == 0) {
            if (i + 1 >= argc) {
                write(STDERR_FILENO, "Missing password argument.\n", ft_strlen("Missing password argument.\n")); 
                return -1;
            }
            ssl->password = argv[++i];
        } else if (ft_strcmp(SALT_HEX_ARG, argv[i]) == 0) {
            if (i + 1 >= argc) {
                write(STDERR_FILENO, "Missing hex salt argument.\n", ft_strlen("Missing hex salt argument.\n")); 
                return -1;
            }
            ssl->salt = argv[++i];
        } else if (ft_strcmp(INIT_VECTOR_HEX_ARG, argv[i]) == 0) {
            if (i + 1 >= argc) {
                write(STDERR_FILENO, "Missing hex initialization vector argument.\n", ft_strlen("Missing hex initialization vector argument.\n")); 
                return -1;
            }
            ssl->init_vector = argv[++i];
        } else {
            break;
        }

        ++i;
    }

    if (ssl->message == NULL
            && read_fd(STDIN_FILENO, (uint8_t **)&ssl->message, &ssl->message_len) == -1) {
        free_ssl(ssl);
        return -1;
    }

    return 0;
}

int check_args(int argc, char **argv, ssl_t *ssl) {
    if (argc < 2) {
        print_usage();
        return -1;
    }

    if (check_command(argv[1], ssl) == -1) {
        return -1;
    }

    int (*check_options[6])(int, char **, ssl_t *) = {
        &check_md5_sha256_options, // MD5
        &check_md5_sha256_options, // SHA256
        &check_base64_options, // BASE64
        &check_des_options, // DES
        &check_des_options, // DES-ECB
        &check_des_options  // DES-CBC
    };

    if (check_options[ssl->algo](argc, argv, ssl) == -1) {
        return -1;
    }

    return 0;
}