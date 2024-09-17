#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "ft_ssl.h"
#include "des.h"


static const uint8_t ep_table[] = EXPANSION_PERMUTATION_TABLE;
static const uint8_t s_boxes[8][4][16] = S_BOXES;
static const uint8_t p_box[32] = P_BOX;
static void mangler(uint8_t *block[8], uint8_t pc2[6]) {
    const uint8_t og_left_half[4], og_right_half[4];
    uint8_t mangled_half[4], expanded[6] = {0};

    ft_memcpy(&og_left_half, *block, 4);
    ft_memcpy(&og_right_half, (*block) + 4, 4);

    // Expansion permutation
    for (int i = 0; i < 48; ++i) {
        int bit_position = ep_table[i] - 1;
        int input_bit = (og_right_half[bit_position / 8] >> (7 - (bit_position % 8))) & 1;

        expanded[i / 8] |= input_bit << (7 - (i % 8));
    }

    // Xor 1
    for (int i = 0; i < 6; ++i) {
        expanded[i] = expanded[i] ^ pc2[i];
    }

    // Keyed Substitution (8 S-Boxes)
    uint32_t result = 0;
    for (int i = 0; i < 8; i++) {
        const uint8_t block6 = (expanded[i / 2] >> (4 * (1 - i % 2))) & 0b00111111; // 6 bits from input
        const int row = ((block6 & 00100000) >> 4) | (block6 & 1);
        const int col = (block6 >> 1) & 0b00001111;
        const uint8_t s_value = s_boxes[i][row][col];

        result = (result << 4) | s_value;
    }
    
    for (int i = 0; i < 4; i++) {
        mangled_half[i] = (result >> (24 - 8 * i)) & 0b11111111;
    }

    // Transposition (P-Box)
    uint32_t input = 0;
    for (int i = 0; i < 4; i++) {
        input = (input << 8) | mangled_half[i];
    }

    for (int i = 0; i < 32; i++) {
        if (input & (1 << (32 - p_box[i]))) {
            result |= (1 << (31 - i));
        }
    }

    for (int i = 0; i < 4; i++) {
        mangled_half[i] = (result >> (24 - 8 * i)) & 0b11111111;
    }

    // Xor 2
    for (int i = 0; i < 4; ++i) {
        mangled_half[i] = mangled_half[i] ^ og_left_half[i];
    }

    ft_memcpy((*block), &og_right_half, 4);
    ft_memcpy((*block) + 4, mangled_half, 4);
}

static void end_32_bit_swap(uint8_t *block[8]) {
    uint8_t temp[8];
    
    memcpy(temp, (*block), 4);
    memcpy((*block), (*block) + 4, 4);
    memcpy((*block) + 4, temp, 4);
}

static void left_circular_shift(uint8_t *key_part, size_t part_size, int shift) {
    uint8_t tmp[4] = {0};
    
    for (int i = 0; i < shift; i++) {
        uint8_t carry = (key_part[0] & 0b10000000) >> 7;

        for (size_t j = 0; j < part_size; j++) {
            tmp[j] = (key_part[j] << 1) | carry;
            carry = (key_part[j] & 0b10000000) >> 7;
        }

        for (size_t j = 0; j < part_size; j++) {
            key_part[j] = tmp[j];
        }
    }
}

static void left_circular_shift_28_bits(uint8_t *key_part, int shift) {
    left_circular_shift(key_part, 4, shift);
}

static void left_circular_shift_56_bits(uint8_t *key56[8], int shift) {
    left_circular_shift_28_bits((uint8_t *)*key56, shift);
    left_circular_shift_28_bits((uint8_t *)((*key56) + 4), shift);
}

static const uint8_t iibp_table[] = INVERSE_INITIAL_BLOCK_PERMUTATION_TABLE;
static void inverse_initial_block_permutation(uint8_t *block[8]) {
    uint8_t tmp[8];

    ft_memcpy(tmp, *block, 8);

    for (int i = 0; i < 64; ++i) {
        int bit = 1 & ((*block)[(iibp_table[i] - 1) / 8] >> ((iibp_table[i] - 1) % 8));
        tmp[i / 8] |= bit << (7 - (i % 8));
    }

    ft_memcpy((*block), tmp, 8);
}

static const uint8_t rkp_table[] = ROUND_KEY_PERMUTATION_TABLE;
static void round_key_permutation(uint8_t *pc2[6], const uint8_t pc1[7]) {
    for (int i = 0; i < 48; ++i) {
        int bit = (pc1[(rkp_table[i] - 1) / 8] >> ((rkp_table[i] - 1) % 8)) & 0x01;
        (*pc2)[i / 8] |= bit << (7 - (i % 8));
    }
}

static const uint8_t ikp_table[] = INITIAL_KEY_PERMUTATION_TABLE;
static void initial_key_permutation(uint8_t *pc1[7], const uint8_t *initial_key) {
    for (int i = 0; i < 56; ++i) {
        int bit = 1 & (initial_key[(ikp_table[i] - 1) / 8] >> ((ikp_table[i] - 1) % 8));
        (*pc1)[i / 8] |= bit << (7 - (i % 8));
    }
}

static const uint8_t ibp_table[] = INITIAL_BLOCK_PERMUTATION_TABLE;
static void initial_block_permutation(uint8_t *block[8], const uint8_t *padded_input) {
    for (int i = 0; i < 64; ++i) {
        int bit = 1 & (padded_input[(ibp_table[i] - 1) / 8] >> ((ibp_table[i] - 1) % 8));
        (*block)[i / 8] |= bit << (7 - (i % 8));
    }
}

static uint8_t *des_algo(uint8_t *padded_input, int len) {
    static const uint8_t left_shifts[16] = {
        1, 1, 2, 2, 2, 2, 1, 1,
        2, 2, 2, 2, 1, 1, 2, 2
    };
    uint8_t block[8];
    uint8_t pc1[7], pc2[6];

    for (int block_index = 0; block_index < len; block_index += 8) {
        initial_block_permutation(&block, padded_input + block_index);
        initial_key_permutation(&pc1, key);

        for (int round = 0; round < 16; ++round) {
            left_circular_shift_56_bits(&pc1, left_shifts[round]);
            round_key_permutation(&pc2, pc1);

            mangler(&block, pc2);
        }

        end_32_bit_swap(&block);
        inverse_initial_block_permutation(&block);
    }
}

static uint8_t *des_padding(const char *input, size_t input_len) {
    uint8_t *padded_input;
    uint8_t padding_len = 8 - input_len % 8;

    if ((padded_input = malloc(sizeof(uint8_t) * (padding_len + 1))) == NULL) {
        print_malloc_error("des_padding");
        return NULL;
    }

    ft_memcpy(padded_input, input, input_len);

    for (uint8_t i = 0; i < padding_len; ++i) {
        padded_input[input_len + i] = padding_len;
    }

    padded_input[padding_len] = 0;
    return padded_input;
}

uint8_t *ft_des(ssl_t *ssl) {
    uint8_t *padded_input = des_padding(ssl->message, ssl->message_len);
    uint8_t *output = NULL;

    if (padded_input == NULL) {
        return NULL;
    }

    des_algo(padded_input, ft_strlen((char *) padded_input));

    free(padded_input);
    return output;
}