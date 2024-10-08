#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <bsd/readpassphrase.h> 

#include "ft_ssl.h"
#include "des.h"
#include "display.h"

static void permutation(uint8_t *dest, const uint8_t *src, int size, const uint8_t *permutation_table);

static const uint8_t s_boxes[8][4][16] = S_BOXES;
static void keyed_substitution(uint8_t *expanded, uint8_t *mangled_half) {
    uint32_t result = 0;

    result |= ((s_boxes[0][((expanded[0] & 0b10000000) >> 6) | ((expanded[0] & 0b00000100) >> 2)][(expanded[0] & 0b01111000) >> 3]) & 0b1111) << 28;
    result |= ((s_boxes[1][((expanded[0] & 0b00000010) >> 0) | ((expanded[1] & 0b00010000) >> 4)][((expanded[0] & 0b00000001) << 3) | ((expanded[1] & 0b11100000) >> 5)]) & 0b1111) << 24;
    result |= ((s_boxes[2][((expanded[1] & 0b00001000) >> 2) | ((expanded[2] & 0b01000000) >> 6)][((expanded[1] & 0b00000111) << 1) | ((expanded[2] & 0b10000000) >> 7)]) & 0b1111) << 20;
    result |= ((s_boxes[3][((expanded[2] & 0b00100000) >> 4) | ((expanded[2] & 0b00000001) >> 0)][((expanded[2] & 0b00011110) >> 1)]) & 0b1111) << 16;
    result |= ((s_boxes[4][((expanded[3] & 0b10000000) >> 6) | ((expanded[3] & 0b00000100) >> 2)][((expanded[3] & 0b01111000) >> 3)]) & 0b1111) << 12;
    result |= ((s_boxes[5][((expanded[3] & 0b00000010) >> 0) | ((expanded[4] & 0b00010000) >> 4)][((expanded[3] & 0b00000001) << 3) | ((expanded[4] & 0b11100000) >> 5)]) & 0b1111) << 8;
    result |= ((s_boxes[6][((expanded[4] & 0b00001000) >> 2) | ((expanded[5] & 0b01000000) >> 6)][((expanded[4] & 0b00000111) << 1) | ((expanded[5] & 0b10000000) >> 7)]) & 0b1111) << 4;
    result |= ((s_boxes[7][((expanded[5] & 0b00100000) >> 4) | ((expanded[5] & 0b00000001) >> 0)][((expanded[5] & 0b00011110) >> 1)]) & 0b1111) << 0;

    mangled_half[0] = (result >> 24) & 0b11111111;
    mangled_half[1] = (result >> 16) & 0b11111111;
    mangled_half[2] = (result >>  8) & 0b11111111;
    mangled_half[3] = (result >>  0) & 0b11111111;

    // OR :
    // for (int i = 0; i < 4; i++) {
    //     mangled_half[i] = (result >> (24 - 8 * i)) & 0b11111111;
    // }
}

static const uint8_t ep_table[] = EXPANSION_PERMUTATION_TABLE;
static const uint8_t p_box[32] = P_BOX;
static void mangler(uint8_t *block, const uint8_t *pc2) {
    uint8_t og_left_half[4], og_right_half[4];
    uint8_t mangled_half[4], expanded[6] = {0};

    ft_memcpy(&og_left_half, block, 4);
    ft_memcpy(&og_right_half, block + 4, 4);

    // Expansion permutation
    permutation(expanded, og_right_half, sizeof(expanded) * 8, ep_table);

    // Xor 1
    for (int i = 0; i < 6; ++i) {
        expanded[i] ^= pc2[i];
    }

    // Keyed Substitution (8 S-Boxes)
    keyed_substitution(expanded, mangled_half);

    // Transposition (P-Box)
    permutation(mangled_half, mangled_half, sizeof(mangled_half) * 8, p_box);

    // Xor 2
    for (int i = 0; i < 4; ++i) {
        mangled_half[i] ^= og_left_half[i];
    }

    ft_memcpy(block, &og_right_half, 4);
    ft_memcpy(block + 4, mangled_half, 4);
}

static void end_32_bit_swap(uint8_t *block) {
    uint8_t temp[8];
    
    ft_memcpy(temp, block, 4);
    ft_memcpy(block, block + 4, 4);
    ft_memcpy(block + 4, temp, 4);
}

static void shift_key(uint8_t *dest, const uint8_t *src, int shift) {
    uint32_t left_half = (((uint32_t) src[0]) << 24)
        | (((uint32_t) src[1]) << 16)
        | (((uint32_t) src[2]) << 8)
        | (((uint32_t) (src[3] & 0b11110000)));
    uint32_t right_half = (((uint32_t) src[3]) << 24)
        | (((uint32_t) src[4]) << 16)
        | (((uint32_t) src[5]) << 8)
        | (((uint32_t) src[6]));

    left_half <<= shift;
    left_half |= (src[0] & (0b11000000 << (2 - shift))) >> (4 - shift);

    right_half <<= shift;
    right_half &= ~(0b11110000000000000000000000000000);
    right_half |= (src[3] & 0b00001110) >> (4 - shift);

    dest[0] = left_half >> 24;
    dest[1] = left_half >> 16;
    dest[2] = left_half >> 8;
    dest[3] = (left_half & 0b11110000) | ((right_half >> 24) & 0b00001111);
    dest[4] = right_half >> 16;
    dest[5] = right_half >> 8;
    dest[6] = right_half;
}

static void permutation(uint8_t *dest, const uint8_t *src, int size, const uint8_t *permutation_table) {
    uint8_t tmp[8] = {0};
    uint8_t bit;

    for (int i = 0; i < size; ++i) {
        bit = (src[(permutation_table[i] - 1) / 8] >> (7 - ((permutation_table[i] - 1) % 8))) & 0b1;
        tmp[i / 8] |= bit << (7 - (i % 8));
    }

    ft_memcpy(dest, tmp, size / 8);
}

static int append_output(uint8_t **output, const uint8_t *block, const int new_size) {
    uint8_t *tmp = NULL;

    if (*output) {
        if ((tmp = malloc(sizeof(uint8_t) * (new_size - 8))) == NULL) {
            print_malloc_error("des_encrypt: tmp malloc");
            return -1;
        }

        ft_memcpy(tmp, *output, new_size - 8);

        if (*output) {
            free(*output);
        }
    }

    if ((*output = malloc(sizeof(uint8_t) * new_size)) == NULL) {
        print_malloc_error("des_encrypt: *output malloc");
        free(tmp);
        return -1;
    }

    if (tmp) {
        ft_memcpy(*output, tmp, new_size - 8);
        free(tmp);
    }

    ft_memcpy(*output + (new_size - 8), block, 8);

    return 0;
}

static const uint8_t ibp_table[] = INITIAL_BLOCK_PERMUTATION_TABLE;
static const uint8_t ikp_table[] = INITIAL_KEY_PERMUTATION_TABLE;
static const uint8_t rkp_table[] = ROUND_KEY_PERMUTATION_TABLE;
static const uint8_t iibp_table[] = INVERSE_INITIAL_BLOCK_PERMUTATION_TABLE;
static const uint8_t left_shifts[16] = LEFT_SHIFTS;
static uint8_t *des_encrypt(ft_des_t *des) {
    uint8_t block[8] = {0};
    uint8_t pc1[16][7] = {0}, pc2[16][6] = {0};

    for (uint64_t block_index = 0; block_index < des->input_len; block_index += 8) {
        if (des->algo == DES_ECB) {
            ft_memset(block, 0, sizeof(block));
        } else if (des->algo == DES || des->algo == DES_CBC) {
            const uint8_t *xor = block_index ? block : des->init_vector;

            for (int i = 0; i < 8; ++i) {
                des->input[block_index + i] ^= xor[i];
            }
        }

        permutation(block, des->input + block_index, sizeof(block) * 8, ibp_table);
        permutation(pc1[0], des->key, sizeof(pc1[0]) * 8, ikp_table);
        for (int kround = 0; kround < 16; ++kround) {
            shift_key(pc1[kround], pc1[kround - (kround ? 1 : 0)], left_shifts[kround]);
            permutation(pc2[kround], pc1[kround], sizeof(pc2[kround]) * 8, rkp_table);
        }

        for (int round = 0; round < 16; ++round) {
            mangler(block, pc2[round]);
        }

        end_32_bit_swap(block);
        permutation(block, block, sizeof(block) * 8, iibp_table);


        if (append_output(&des->output, block, block_index + 8) == -1) {
            return NULL;
        }
        des->output_len += 8;
    }

    return des->output;
}

static uint8_t *des_decrypt(ft_des_t *des) {
    uint8_t block[8] = {0};
    uint8_t pc1[16][7] = {0}, pc2[16][6] = {0};

    for (uint64_t block_index = 0; block_index < des->input_len; block_index += 8) {
        if (des->algo == DES_ECB) {
            ft_memset(block, 0, sizeof(block));
        }

        permutation(block, des->input + block_index, sizeof(block) * 8, ibp_table);
        permutation(pc1[0], des->key, sizeof(pc1[0]) * 8, ikp_table);
        for (int kround = 0; kround < 16; ++kround) {
            shift_key(pc1[kround], pc1[kround - (kround ? 1 : 0)], left_shifts[kround]);
            permutation(pc2[kround], pc1[kround], sizeof(pc2[kround]) * 8, rkp_table);
        }

        for (int round = 15; round >= 0; --round) {
            mangler(block, pc2[round]);
        }

        end_32_bit_swap(block);
        permutation(block, block, sizeof(block) * 8, iibp_table);

        if (des->algo == DES || des->algo == DES_CBC) {
            const uint8_t *xor = block_index ? des->input + (block_index - 8) : des->init_vector;

            for (int i = 0; i < 8; ++i) {
                block[i] ^= xor[i];
            }
        }


        if (append_output(&des->output, block, block_index + 8) == -1) {
            return NULL;
        }
        des->output_len += 8;
    }

    if (des->output[des->output_len - 1] > 8) {
        ft_dprintf(STDERR_FILENO, "bad decrypt\n");
        des->output_len -= 8;
    } else {
        des->output_len -= des->output[des->output_len - 1];
        des->output[des->output_len] = 0;
    }

    return des->output;
}

static void check_hex_len(const size_t len) {
    if (len < 16) {
        print_hex_string_too_short();
    } else if (len > 16) {
        print_hex_string_too_long();
    }
}

static uint8_t *get_input(const char *ssl_input, size_t ssl_input_len, ssl_option_t options, uint64_t *input_len) {
    uint8_t *input;
    uint8_t padding_len = 8 - ssl_input_len % 8;

    if (options & DECRYPT_MODE_OPTION) {
        if (options & DE_ENCODE_IN_OUTPUT_BASE64_OPTION) {
            if ((input = (uint8_t *) ft_base64(ssl_input, ssl_input_len, DECODE_MODE_OPTION, input_len)) == NULL) {
                return NULL;
            }

            return input;
        } else {
            if ((input = malloc(sizeof(uint8_t) * (ssl_input_len))) == NULL) {
                print_malloc_error("get_input");
                return NULL;
            }

            ft_memcpy(input, ssl_input, ssl_input_len);
            *input_len = ssl_input_len;

            return input;
        }
    }

    if ((input = malloc(sizeof(uint8_t) * (ssl_input_len + padding_len + 1))) == NULL) {
        print_malloc_error("get_input");
        return NULL;
    }

    ft_memcpy(input, ssl_input, ssl_input_len);

    for (uint8_t i = 0; i < padding_len; ++i) {
        input[ssl_input_len + i] = padding_len;
    }

    input[ssl_input_len + padding_len] = 0;
    *input_len = ssl_input_len + padding_len;
    return input;
}

static uint8_t get_hex_val(uint8_t hex) {
    if (hex >= 'a' && hex <= 'z') {
        return hex - 'a' + 10;
    } else if (hex >= 'A' && hex <= 'Z') {
        return hex - 'A' + 10;
    } else if (hex >= '0' && hex <= '9') {
        return hex - '0';
    }

    return 0;
}

static int get_iv(uint8_t *iv, const char *ssl_iv, const uint8_t *des_key, const bool was_key_generated ) {
    if (ssl_iv) {
        const uint8_t ssl_iv_len = ft_strlen(ssl_iv);

        for (int i = 0; i < ssl_iv_len && i < 16; ++i) {
            iv[i / 2] |= get_hex_val(ssl_iv[i]) << (4 * ((i + 1) % 2));
        }

        check_hex_len(ssl_iv_len);
        for (int i = (ssl_iv_len + 1) / 2; i < 8; ++i) {
            iv[i] = 0;
        }
    } else if (was_key_generated) {
        ft_memcpy(iv, des_key + 8, 8);
    } else {
        ft_dprintf(STDERR_FILENO, "iv undefined\n");
        return -1;
    }

    return 0;
}

static int get_salt(uint8_t *salt, const char *ssl_salt, const uint8_t *input, const bool is_salted, const bool decrypt_mode) {
    uint64_t ssl_salt_len = ft_strlen(ssl_salt);

    if (ssl_salt) {
        for (uint64_t i = 0; i < ssl_salt_len && i < 16; ++i) {
            salt[i / 2] |= get_hex_val(ssl_salt[i]) << (4 * ((i + 1) % 2));
        }

        check_hex_len(ssl_salt_len);
        for (uint64_t i = (ssl_salt_len + 1) / 2; i < SALT_LEN; ++i) {
            salt[i] = 0;
        }

        if (is_salted && ft_memcmp(salt, input + ft_strlen(SALTED__STR), SALT_LEN)) {
            ft_dprintf(STDERR_FILENO, "bad decrypt\n");
            return -1;
        }
    } else if (is_salted) {
        for (int i = 0; i < SALT_LEN; ++i) {
            salt[i] = input[8 + i];
        }
    } else if (decrypt_mode) {
        ft_dprintf(STDERR_FILENO, "bad magic number\n");
        return -1;
    } else {
        time_t t;

        srand((unsigned int) time(&t));
        for (uint64_t i = 0; i < SALT_LEN; ++i) {
            salt[i] = rand() % 256;
        }
    }

    return 0;
}

static char *get_password(const char *ssl_pwd) {
    char *pwd;
    char pwd_verif[256] = {0};

    if (ssl_pwd) {
        int len = ft_strlen(ssl_pwd);
        if ((pwd = malloc(sizeof(char) * (len + 1))) == NULL) {
            print_malloc_error("get_password");
            return NULL;
        }

        ft_memcpy(pwd, ssl_pwd, len + 1);

        return pwd;
    }

    if ((pwd = malloc(sizeof(char) * 256)) == NULL) {
        print_malloc_error("get_password");
        return NULL;
    }

    ft_memset(pwd, 0, 256);

    while (readpassphrase("Enter a password: ", pwd, 256, 0) == NULL) {
        ft_dprintf(STDERR_FILENO, "Invalid password, retry.\n");
    }

    while (readpassphrase("Verifying - Enter a password: ", pwd_verif, 256, 0) == NULL) {
        ft_dprintf(STDERR_FILENO, "Invalid password verification, retry.\n");
    }

    if (ft_strcmp(pwd, pwd_verif)) {
        ft_dprintf(STDERR_FILENO, "Verify failure\nbad password read\n");
        free(pwd);
        return NULL;
    }

    return pwd;
}

static int get_key(uint8_t *key, const char *ssl_key, const uint8_t *key16) {
    if (ssl_key) {
        uint8_t ssl_key_len = ft_strlen(ssl_key);

        for (int i = 0; i < ssl_key_len && i < 16; ++i) {
            if (!((ssl_key[i] >= 'a' && ssl_key[i] <= 'f')
                    || (ssl_key[i] >= 'A' && ssl_key[i] <= 'F')
                    || (ssl_key[i] >= '0' && ssl_key[i] <= '9'))) {
                ft_dprintf(STDERR_FILENO, "Invalid key near `%s`.\n", &ssl_key[i]);
                return -1;
            }

            key[i / 2] |= get_hex_val(ssl_key[i]) << (4 * ((i + 1) % 2));
        }

        check_hex_len(ssl_key_len);
        for (int i = (ssl_key_len + 1) / 2; i < 8; ++i) {
            key[i] = 0;
        }
    } else {
        ft_memcpy(key, key16, 8);
    }

    return 0;
}

void free_des(ft_des_t *des, const bool free_output) {
    if (des->input) {
        free(des->input);
        des->input = NULL;
    }

    if (des->password) {
        free(des->password);
        des->password = NULL;
    }

    if (free_output && des->output) {
        free(des->output);
        des->output = NULL;
    }
}

static int init_des(ft_des_t *des, const ssl_t *ssl) {
    if ((des->input = get_input(ssl->message, ssl->message_len, ssl->options, &des->input_len)) == NULL) {
        return -1;
    }

    if ((ssl->password || !ssl->key) && (des->password = get_password(ssl->password)) == NULL) {
        return -1;
    }

    const bool is_salted = (ssl->options & DECRYPT_MODE_OPTION)
        && des->input_len >= 24
        && ft_memcmp(des->input, SALTED__STR, ft_strlen(SALTED__STR)) == 0;

    if ((ssl->salt || ssl->password || !ssl->key)
            && get_salt(des->salt, ssl->salt, des->input, is_salted, (ssl->options & DECRYPT_MODE_OPTION)) == -1) {
        return -1;
    }

    if ((!ssl->key || des->password) && gen_key(des->key16, des->password, des->salt) == -1) {
        ft_dprintf(STDERR_FILENO, "Error in key generation.\n");
        return -1;
    }

    if ((ssl->algo == DES || ssl->algo == DES_CBC)
            && get_iv(des->init_vector, ssl->init_vector, des->key16, (!ssl->key || des->password)) == -1) {
        return -1;
    }

    if (get_key(des->key, ssl->key, des->key16) == -1) {
        return -1;
    }

    if (is_salted) {
        uint8_t *tmp = malloc(sizeof(uint8_t) * (des->input_len - 16));

        if (tmp == NULL) {
            print_malloc_error("init_des");
            return -1;
        }

        ft_memcpy(tmp, des->input + 16, des->input_len - 16);
        free(des->input);

        des->input = tmp;
        des->input_len -= 16;
    }

    return 0;
}

static void display_key_iv_salt(ft_des_t *des) {
    ft_dprintf(STDOUT_FILENO, "salt=");
    for (uint64_t i = 0; i < SALT_LEN; ++i) {
        ft_dprintf(STDOUT_FILENO, "%02X", des->salt ? des->salt[i] : 0);
    }
    ft_dprintf(STDOUT_FILENO, "\nkey=");
    for (int i = 0; i < 8; ++i) {
        ft_dprintf(STDOUT_FILENO, "%02X", des->key[i]);
    }
    ft_dprintf(STDOUT_FILENO, "\n");
    if (des->algo == DES || des->algo == DES_CBC) {
        ft_dprintf(STDOUT_FILENO, "iv =");
        for (int i = 0; i < 8; ++i) {
            ft_dprintf(STDOUT_FILENO, "%02X", des->init_vector[i]);
        }
        ft_dprintf(STDOUT_FILENO, "\n");
    }
}

uint8_t *ft_des(ssl_t *ssl) {
    ft_des_t des = {
        .algo           = ssl->algo,
        .input          = NULL,
        .input_len      = 0,
        .password       = NULL,
        .salt           = {0},
        .key16          = {0},
        .key            = {0},
        .init_vector    = {0},
        .output         = NULL,
        .output_len     = 0
    };

    if (init_des(&des, ssl) == -1) {
        free_des(&des, true);
        return NULL;
    }

    if (ssl->init_vector && !(ssl->algo == DES || ssl->algo == DES_CBC)) {
        ft_dprintf(STDERR_FILENO, "warning: iv not used by this cipher\n");
    }

    if (ssl->options & DISPLAY_KEY_IV_SALT_OPTION) {
        display_key_iv_salt(&des);
    }

    if ((ssl->options & DECRYPT_MODE_OPTION ? des_decrypt(&des) : des_encrypt(&des)) == NULL) {
        free_des(&des, true);
        return NULL;
    }

    ssl->output = des.output;
    ssl->output_len = des.output_len;

    if (ssl->options & ENCRYPT_MODE_OPTION && ssl->options & DE_ENCODE_IN_OUTPUT_BASE64_OPTION) {
        uint8_t *tmp = NULL;

        if ((tmp = (uint8_t *) ft_base64((char *) des.output, des.output_len, ENCODE_MODE_OPTION, &ssl->output_len)) == NULL) {
            free_des(&des, true);
            return NULL;
        }

        free(ssl->output);
        ssl->output = tmp;
    } else if (!(ssl->key && !ssl->password) && !ssl->salt && (ssl->options & ENCRYPT_MODE_OPTION)) {
        uint8_t *tmp = NULL;

        if ((tmp = malloc(sizeof(uint8_t) * (des.output_len + 16))) == NULL) {
            free_des(&des, true);
            return NULL;
        }

        ft_memcpy(tmp, SALTED__STR, 8);
        ft_memcpy(tmp + 8, des.salt, 8);
        ft_memcpy(tmp + 16, des.output, des.output_len);

        free(des.output);
        ssl->output = tmp;
        ssl->output_len = des.output_len + 16;
    }

    free_des(&des, false);
    return ssl->output;
}