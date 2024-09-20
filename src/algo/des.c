#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "ft_ssl.h"
#include "des.h"
    #include "display.h"

static void permutation(uint8_t *dest, const uint8_t *src, int size, const uint8_t *permutation_table);

static const uint8_t ep_table[] = EXPANSION_PERMUTATION_TABLE;
static const uint8_t s_boxes[8][4][16] = S_BOXES;
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
        expanded[i] = expanded[i] ^ pc2[i];
    }

    // Keyed Substitution (8 S-Boxes)
    uint32_t result = 0;

    result |= (s_boxes[0][((expanded[0] & 0b10000000) >> 6) | ((expanded[0] & 0b00000100) >> 2)][(expanded[0] & 0b01111000) >> 3]) << 28;
    result |= (s_boxes[1][((expanded[0] & 0b00000010) >> 0) | ((expanded[1] & 0b00010000) >> 4)][((expanded[0] & 0b00000001) << 3) | ((expanded[1] & 0b11100000) >> 5)]) << 24;
    result |= (s_boxes[2][((expanded[1] & 0b00001000) >> 2) | ((expanded[2] & 0b01000000) >> 6)][((expanded[1] & 0b00000111) << 1) | ((expanded[2] & 0b10000000) >> 7)]) << 20;
    result |= (s_boxes[3][((expanded[2] & 0b00100000) >> 4) | ((expanded[2] & 0b00000001) >> 0)][((expanded[2] & 0b00011110) >> 1)]) << 16;
    result |= (s_boxes[4][((expanded[3] & 0b10000000) >> 6) | ((expanded[3] & 0b00000100) >> 2)][((expanded[3] & 0b01111000) >> 3)]) << 12;
    result |= (s_boxes[5][((expanded[3] & 0b00000010) >> 0) | ((expanded[4] & 0b00010000) >> 4)][((expanded[3] & 0b00000001) << 3) | ((expanded[4] & 0b11100000) >> 5)]) << 8;
    result |= (s_boxes[6][((expanded[4] & 0b00001000) >> 2) | ((expanded[5] & 0b01000000) >> 6)][((expanded[4] & 0b00000111) << 1) | ((expanded[5] & 0b10000000) >> 7)]) << 4;
    result |= (s_boxes[7][((expanded[5] & 0b00100000) >> 4) | ((expanded[5] & 0b00000001) >> 0)][((expanded[5] & 0b00011110) >> 1)]) << 0;

    mangled_half[0] = (result >> 24) & 0b11111111;
    mangled_half[1] = (result >> 16) & 0b11111111;
    mangled_half[2] = (result >>  8) & 0b11111111;
    mangled_half[3] = (result >>  0) & 0b11111111;

    // for (int i = 0; i < 4; i++) {
    //     mangled_half[i] = (result >> (24 - 8 * i)) & 0b11111111;
    // }


    // Transposition (P-Box)
    permutation(mangled_half, mangled_half, sizeof(mangled_half) * 8, p_box);

    // Xor 2
    for (int i = 0; i < 4; ++i) {
        mangled_half[i] = mangled_half[i] ^ og_left_half[i];
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

static void shift_key(uint8_t *key, int shift) {
    uint32_t left_half = (((uint32_t) key[0]) << 24)
        | (((uint32_t) key[1]) << 16)
        | (((uint32_t) key[2]) << 8)
        | (((uint32_t) (key[3] & 0b11110000)));
    uint32_t right_half = (((uint32_t) key[3]) << 24)
        | (((uint32_t) key[4]) << 16)
        | (((uint32_t) key[5]) << 8)
        | (((uint32_t) key[6]));

    left_half <<= shift;
    left_half |= (key[0] & (0b11000000 << (2 - shift))) >> (4 - shift);

    right_half <<= shift;
    right_half &= ~(0b11110000000000000000000000000000);
    right_half |= (key[3] & 0b00001111) >> (4 - shift);

    key[0] = left_half >> 24;
    key[1] = left_half >> 16;
    key[2] = left_half >> 8;
    key[3] = (left_half & 0b11110000) | ((right_half >> 24) & 0b00001111);
    key[4] = right_half >> 16;
    key[5] = right_half >> 8;
    key[6] = right_half;
}

static void permutation(uint8_t *dest, const uint8_t *src, int size, const uint8_t *permutation_table) {
    uint8_t tmp[8] = {0};
    uint8_t bit;

    for (int i = 0; i < size; ++i) {
        bit = (src[(permutation_table[i] - 1) / 8] >> ((permutation_table[i] - 1) % 8)) & 0x01;
        tmp[i / 8] |= bit << (7 - (i % 8));
    }

    ft_memcpy(dest, tmp, size / 8);
}

static const uint8_t ibp_table[] = INITIAL_BLOCK_PERMUTATION_TABLE;
static const uint8_t ikp_table[] = INITIAL_KEY_PERMUTATION_TABLE;
static const uint8_t rkp_table[] = ROUND_KEY_PERMUTATION_TABLE;
static const uint8_t iibp_table[] = INVERSE_INITIAL_BLOCK_PERMUTATION_TABLE;
static const uint8_t left_shifts[16] = LEFT_SHIFTS;
static uint8_t *des_algo(ft_des_t *des) {
    uint8_t block[8];
    uint8_t pc1[7] = {0}, pc2[6] = {0};

    for (uint64_t block_index = 0; block_index < des->p_input_len; block_index += 8) {
        ft_memset(block, 0, sizeof(block));
        permutation(block, des->padded_input + block_index, sizeof(block) * 8, ibp_table);
        permutation(pc1, des->key, sizeof(pc1) * 8, ikp_table);

        for (int round = 0; round < 16; ++round) {
            shift_key(pc1, left_shifts[round]);
            permutation(pc2, pc1, sizeof(pc2) * 8, rkp_table);

            mangler(block, pc2);
        }

        end_32_bit_swap(block);
        permutation(block, block, sizeof(block) * 8, iibp_table);
    }

    ft_dprintf(1, "\n");
    ft_hexdump(block, 8, 1);

    return NULL;
}

static uint8_t *des_padding(const char *input, size_t input_len) {
    uint8_t *padded_input;
    uint8_t padding_len = 8 - input_len % 8;

    if ((padded_input = malloc(sizeof(uint8_t) * (input_len + padding_len + 1))) == NULL) {
        print_malloc_error("des_padding");
        return NULL;
    }

    ft_memcpy(padded_input, input, input_len);

    for (uint8_t i = 0; i < padding_len; ++i) {
        padded_input[input_len + i] = padding_len;
    }

    padded_input[input_len + padding_len] = 0;
    return padded_input;
}

uint8_t *ft_des(ssl_t *ssl) {
    ft_des_t des = {
        .padded_input   = des_padding(ssl->message, ssl->message_len),
        .p_input_len    = ft_strlen((char *) des.padded_input),
        .password       = NULL,
        .salt           = NULL,
        .key            = (uint8_t *) "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB",
        .init_vector    = NULL,
        .output         = NULL
    };

    if (des.padded_input == NULL) {
        return NULL;
    }

    des.output = des_algo(&des);

    free(des.padded_input);
    return des.output;
}