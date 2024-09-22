#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <bsd/readpassphrase.h> 

#include "ft_ssl.h"
#include "des.h"

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

    for (uint64_t block_index = 0; block_index < des->p_input_len; block_index += 8) {
        if (des->algo == DES_ECB) {
            ft_memset(block, 0, sizeof(block));
        } else if (des->algo == DES || des->algo == DES_CBC) {
            const uint8_t *xor = block_index ? block : des->init_vector;

            for (int i = 0; i < 8; ++i) {
                des->padded_input[block_index + i] ^= xor[i];
            }
        }

        permutation(block, des->padded_input + block_index, sizeof(block) * 8, ibp_table);
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

    for (uint64_t block_index = 0; block_index < des->p_input_len; block_index += 8) {
        if (des->algo == DES_ECB) {
            ft_memset(block, 0, sizeof(block));
        }

        permutation(block, des->padded_input + block_index, sizeof(block) * 8, ibp_table);
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
            const uint8_t *xor = block_index ? des->padded_input - 8 : des->init_vector;

            for (int i = 0; i < 8; ++i) {
                block[i] ^= xor[i];
            }
        }


        if (append_output(&des->output, block, block_index + 8) == -1) {
            return NULL;
        }
        des->output_len += 8;
    }

    #include "display.h"
    ft_dprintf(1, "old len: %d\n", des->output_len);
    ft_hexdump(des->output, des->output_len, 1);
    des->output_len -= des->output[des->output_len - 1];
    ft_dprintf(1, "new len: %d\n", des->output_len);
    return des->output;
}

static uint8_t *get_input(const char *input, size_t input_len, ssl_option_t options, uint64_t *len) {
    uint8_t *output;
    uint8_t padding_len = 8 - input_len % 8;

    if (options & (DECRYPT_MODE_OPTION | DE_ENCODE_IN_OUTPUT_BASE64_OPTION)) {
        if ((output = (uint8_t *) ft_base64(input, input_len, DECODE_MODE_OPTION)) == NULL) {
            return NULL;
        }

        return output;
    }

    if ((output = malloc(sizeof(uint8_t) * (input_len + padding_len + 1))) == NULL) {
        print_malloc_error("get_input");
        return NULL;
    }

    ft_memcpy(output, input, input_len);

    for (uint8_t i = 0; i < padding_len; ++i) {
        output[input_len + i] = padding_len;
    }

    output[input_len + padding_len] = 0;
    *len = input_len + padding_len;
    return output;
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

static uint8_t *get_iv(const char *ssl_iv) {
    uint8_t ssl_iv_len = ssl_iv ? ft_strlen(ssl_iv) : 0;
    uint8_t *iv = NULL;

    if ((iv = malloc(sizeof(uint8_t) * 8)) == NULL) {
        print_malloc_error("get_iv");
        return NULL;
    }

    if (ssl_iv) {
        for (int i = 0; i < ssl_iv_len && i < 16; ++i) {
            iv[i / 2] |= get_hex_val(ssl_iv[i]) << (4 * ((i + 1) % 2));
        }

        for (int i = (ssl_iv_len + 1) / 2; i < 8; ++i) {
            iv[i] = 0;
        }
    } else {
        for (int i = 0; i < 8; ++i) {
            iv[i] = rand() % 256;
        }
    }

    return iv;
}

static uint8_t *get_salt(const char *ssl_salt, uint64_t *salt_len) {
    uint8_t *salt = NULL;

    *salt_len = ssl_salt ? ft_strlen(ssl_salt) : 8;

    if ((salt = malloc(sizeof(uint8_t) * 8)) == NULL) {
        print_malloc_error("get_salt");
        return NULL;
    }

    if (ssl_salt) {
        for (uint64_t i = 0; i < *salt_len && i < 16; ++i) {
            salt[i / 2] |= get_hex_val(ssl_salt[i]) << (4 * ((i + 1) % 2));
        }

        for (uint64_t i = (*salt_len + 1) / 2; i < 8; ++i) {
            salt[i] = 0;
        }
    } else {
        for (uint64_t i = 0; i < *salt_len; ++i) {
            salt[i] = rand() % 256;
        }
    }

    return salt;
}

static char *get_password(const char *ssl_pwd, const char *key) {
    char *pwd;

    if (key) {
        return NULL;
    }

    if (ssl_pwd) {
        int len = ft_strlen(ssl_pwd);
        if ((pwd = malloc(sizeof(char) * (len + 1))) == NULL) {
            print_malloc_error("get_password");
            return NULL;
        }

        ft_memcpy(pwd, ssl_pwd, len);

        return pwd;
    }

    if ((pwd = malloc(sizeof(char) * 256)) == NULL) {
        print_malloc_error("get_password");
        return NULL;
    }

    ft_memset(pwd, 0, 256);

    while (readpassphrase("Enter a password: ", pwd, 256, 0) == NULL || !pwd[0]) {
        ft_dprintf(STDERR_FILENO, "Invalid password, retry.\n");
    }

    return pwd;
}

static int gen_key(uint8_t *key, const char *password, uint64_t password_len, const uint8_t *salt, uint64_t salt_len) {


    (void)key;
    (void)password;
    (void)password_len;
    (void)salt;
    (void)salt_len;
    return -1;
}

static uint8_t *get_key(const char *ssl_key, const char *password, uint64_t password_len, const uint8_t *salt, uint64_t salt_len) {
    uint8_t ssl_key_len = ssl_key ? ft_strlen(ssl_key) : 8;
    uint8_t *key = NULL;

    for (int i = 0; i < ssl_key_len && i < 8; ++i) {
        if (!((ssl_key[i] >= 'a' && ssl_key[i] <= 'f')
                || (ssl_key[i] >= 'A' && ssl_key[i] <= 'F')
                || (ssl_key[i] >= '0' && ssl_key[i] <= '9'))) {
            ft_dprintf(STDERR_FILENO, "Invalid key near `%s`.\n", &ssl_key[i]);
            return NULL;
        }
    }

    if ((key = malloc(sizeof(uint8_t) * 8)) == NULL) {
        print_malloc_error("get_key");
        return NULL;
    }

    ft_memset(key, 0, 8);

    if (ssl_key) {
        for (int i = 0; i < ssl_key_len && i < 16; ++i) {
            key[i / 2] |= get_hex_val(ssl_key[i]) << (4 * ((i + 1) % 2));
        }

        for (int i = (ssl_key_len + 1) / 2; i < 8; ++i) {
            key[i] = 0;
        }
    } else {
        if (gen_key(key, password, password_len, salt, salt_len) == -1) {
            ft_dprintf(STDERR_FILENO, "Error in key generation.\n");
            free(key);
            return NULL;
        }
    }

    return key;
}

void free_des(ft_des_t *des, uint8_t free_output) {
    if (des->padded_input) {
        free(des->padded_input);
    }

    if (des->salt) {
        free(des->salt);
    }

    if (des->password) {
        free(des->password);
    }

    if (des->key) {
        free(des->key);
    }

    if (free_output && des->output) {
        free(des->output);
    }
}

uint8_t *ft_des(ssl_t *ssl) {
    ft_des_t des = {
        .algo           = ssl->algo,
        .padded_input   = get_input(ssl->message, ssl->message_len, ssl->options, &des.p_input_len),
        // .p_input_len    = des.p_input_len,
        .password       = ssl->key ? NULL : get_password(ssl->password, ssl->key),
        .salt           = ssl->key ? NULL : get_salt(ssl->salt, &des.salt_len),
        // .salt_len    = des.salt_len,
        .key            = get_key(ssl->key, des.password, ft_strlen(des.password), des.salt, des.salt_len),
        .init_vector    = ssl->algo == DES_ECB ? NULL : get_iv(ssl->init_vector),
        .output         = NULL,
        .output_len     = 0
    };

    if (des.padded_input == NULL || des.key == NULL
            || (!ssl->key && (!des.password || !des.salt))) {
        free_des(&des, 1);
        return NULL;
    }

    if (ssl->options & DECRYPT_MODE_OPTION) {
        if (des_decrypt(&des) == NULL) {
            free_des(&des, 1);
            return NULL;
        }
    } else {
        if (des_encrypt(&des) == NULL) {
            free_des(&des, 1);
            return NULL;
        }
    }

    ssl->output = des.output;
    ssl->output_len = des.output_len;

    if (ssl->options & (ENCRYPT_MODE_OPTION | DE_ENCODE_IN_OUTPUT_BASE64_OPTION)) {
        uint8_t *tmp = NULL;

        if ((tmp = (uint8_t *) ft_base64((char *) des.output, des.output_len, DECODE_MODE_OPTION)) == NULL) {
            free_des(&des, 1);
            return NULL;
        }

        free(ssl->output);
        ssl->output = tmp;
    }

    free_des(&des, 0);
    return ssl->output;
}