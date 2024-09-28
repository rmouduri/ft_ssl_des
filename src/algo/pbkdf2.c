#include "ft_ssl.h"
#include "ft_sha256.h"
#include "des.h"
#include "display.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE 32
#define BLOCK_SIZE 64
#define KEY_SIZE 8
#define ITERATIONS 10000


static int mini_SHA256_Padding(const uint8_t *input, const size_t input_len, ft_sha256_t *sha256) {
    uint8_t *padded_input;

    sha256->input_len = 64 + (64 * ((input_len / 64) + (input_len % 64 >= 56 ? 1 : 0)));
    padded_input = malloc(sizeof(uint8_t) * sha256->input_len);

    if (padded_input == NULL) {
        print_malloc_error("mini_SHA256_Padding");
        return -1;
    }

    ft_memcpy(padded_input, input, input_len);
    ft_memset(padded_input + input_len, 0b10000000, 1);
    ft_memset(padded_input + input_len + 1, 0, sha256->input_len - (input_len + 1));

    uint64_t len_in_bits = input_len * 8;
    uint8_t *p = padded_input + (sha256->input_len - 8);
    /* Big endian :
        len_in_bits = 0x123456789ABCDEF0

        each loop of i:
            p[i] = len_in_bits & 0xFF = 0xF0 (The 8 lowest bits)
            len_in_bits >>= 8
            len_in_bits = 0x00123456789ABCDE (Next time, the 8 lowest bits will be 0xDE)
            p = [__, __, __, __, __, __, __, 0xF0]
    */ 
    for (int i = 7; i >= 0; --i) {
        p[i] = len_in_bits & 0xFF;
        len_in_bits >>= 8;
    }

    sha256->input = (uint32_t *) padded_input;
    return 0;
}

static void mini_SHA256_Algo(ft_sha256_t *sha256) {
    const uint32_t k[64] = K;
    uint32_t tmp_state[8];
    uint32_t w[64];
    uint32_t s0, s1, S0, S1, temp1, temp2, Ch, Maj;


    sha256->state[A] = 0x6a09e667;
    sha256->state[B] = 0xbb67ae85;
    sha256->state[C] = 0x3c6ef372;
    sha256->state[D] = 0xa54ff53a;
    sha256->state[E] = 0x510e527f;
    sha256->state[F] = 0x9b05688c;
    sha256->state[G] = 0x1f83d9ab;
    sha256->state[H] = 0x5be0cd19;

    for (uint64_t chunk_index = 0; chunk_index < sha256->input_len; chunk_index += 64) {
        for (uint8_t i = 0; i < 16; ++i) {
            w[i] = sha256->input[(chunk_index / 4) + i];
            /* Big endian in 1 line, we place the byte at the correct future position then we extract it:
                0x12345678 >> 24 = 0x00000012
                (0x12345678 >> 8) & 0x0000FF00 = 0x00003400
                (0x12345678 << 8) & 0x00FF0000 = 0x00560000
                0x12345678 << 24 = 0x78000000
                0x00000012 | 0x00003400 | 0x00560000 | 0x78000000 = 0x78563412
            */
            w[i] =  (w[i] >> 24) |
                    ((w[i] >> 8) & 0x0000FF00) |
                    ((w[i] << 8) & 0x00FF0000) |
                    (w[i] << 24);
        }

        for (uint8_t i = 16; i < 64; ++i) {
            s0 = ROTATE_RIGHT(w[i - 15], 7) ^ ROTATE_RIGHT(w[i - 15], 18) ^ SHIFT_RIGHT(w[i - 15], 3);
            s1 = ROTATE_RIGHT(w[i - 2], 17) ^ ROTATE_RIGHT(w[i - 2], 19) ^ SHIFT_RIGHT(w[i - 2], 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        for (uint8_t state_index = A; state_index <= H; ++state_index) {
            tmp_state[state_index] = sha256->state[state_index];
        }

        for (uint8_t i = 0; i < 64; ++i) {
            S1 = ROTATE_RIGHT(tmp_state[E], 6) ^ ROTATE_RIGHT(tmp_state[E], 11) ^ ROTATE_RIGHT(tmp_state[E], 25);
            Ch = (tmp_state[E] & tmp_state[F]) ^ ((~tmp_state[E]) & tmp_state[G]);
            temp1 = tmp_state[H] + S1 + Ch + k[i] + w[i];

            S0 = ROTATE_RIGHT(tmp_state[A], 2) ^ ROTATE_RIGHT(tmp_state[A], 13) ^ ROTATE_RIGHT(tmp_state[A], 22);
            Maj = (tmp_state[A] & tmp_state[B]) ^ (tmp_state[A] & tmp_state[C]) ^ (tmp_state[B] & tmp_state[C]);
            temp2 = S0 + Maj;

            tmp_state[H] = tmp_state[G];
            tmp_state[G] = tmp_state[F];
            tmp_state[F] = tmp_state[E];
            tmp_state[E] = tmp_state[D] + temp1;
            tmp_state[D] = tmp_state[C];
            tmp_state[C] = tmp_state[B];
            tmp_state[B] = tmp_state[A];
            tmp_state[A] = temp1 + temp2;
        }

        for (uint8_t state_index = A; state_index <= H; ++state_index) {
            sha256->state[state_index] += tmp_state[state_index];
        }
    }
}

static int mini_sha256(uint8_t *dest, const uint8_t *input, const size_t input_len) {
    ft_sha256_t     sha256;

    if (mini_SHA256_Padding(input, input_len, &sha256) == -1) {
        return -1;
    }

    mini_SHA256_Algo(&sha256);

    free(sha256.input);

    /* Big Endian
        Same story, but the hash is interpreted as a 32-bit array of length 8 (256)
    */
    for (int i = 0; i < 8; ++i) {
        dest[i * 4] = (sha256.state[i] >> 24) & 0xFF;
        dest[i * 4 + 1] = (sha256.state[i] >> 16) & 0xFF;
        dest[i * 4 + 2] = (sha256.state[i] >> 8) & 0xFF;
        dest[i * 4 + 3] = sha256.state[i] & 0xFF;
    }

    return 0;
}

static int hmac(uint8_t *dest, const uint8_t *secret, const uint8_t *msg, size_t msg_len) {
    uint8_t i_key_pad[BLOCK_SIZE] = {0}, o_key_pad[BLOCK_SIZE] = {0};

    for (int i = 0; i < BLOCK_SIZE; ++i) {
        i_key_pad[i] = secret[i] ^ 0x36;
        o_key_pad[i] = secret[i] ^ 0x5c;
    }

    // Inner Hash
    uint8_t inner_input[sizeof(i_key_pad) + msg_len], inner_hash[SHA256_BLOCK_SIZE] = {0};

    ft_memcpy(inner_input, i_key_pad, sizeof(i_key_pad));
    ft_memcpy(inner_input + sizeof(i_key_pad), msg, msg_len);

    if (mini_sha256(inner_hash, inner_input, sizeof(inner_input)) == -1) {
        return -1;
    }

    // Outer Hash
    uint8_t outer_input[sizeof(o_key_pad) + sizeof(inner_hash)], hmac_result[SHA256_BLOCK_SIZE] = {0};

    ft_memcpy(outer_input, o_key_pad, sizeof(o_key_pad));
    ft_memcpy(outer_input + sizeof(o_key_pad), inner_hash, sizeof(inner_hash));

    if (mini_sha256(hmac_result, outer_input, sizeof(outer_input)) == -1) {
        return -1;
    }

    ft_memcpy(dest, hmac_result, SHA256_BLOCK_SIZE);

    return 0;
}

static int pbkdf2_sha256(uint8_t *key, const uint8_t *password, const size_t password_len, const uint8_t *salt) {
    const int blockn = 1;
    uint8_t block[SALT_LEN + sizeof(blockn)] = {0};
    uint8_t U[32] = {0}, U_tmp[32] = {0}, T[32] = {0};
    uint8_t secret[64] = {0};


    if (password_len > BLOCK_SIZE) {
        if (mini_sha256(secret, password, password_len) == -1) {
            return -1;
        }
    } else {
        ft_memcpy(secret, password, password_len);
    }

    ft_memcpy(block, salt, SALT_LEN);
    // Big endian size
    for (int i = 0; i < 4; ++i) {
        block[SALT_LEN + i] = (blockn >> (24 - (8 * i))) & 0xff;
    }

    if (hmac(U, secret, block, SALT_LEN + sizeof(blockn)) == -1) {
        return -1;
    }

    ft_memcpy(T, U, 32);

    for (int i = 1; i < ITERATIONS; ++i) {
        ft_memcpy(U_tmp, U, 32);
        if (hmac(U, secret, U_tmp, 32) == -1) {
            return -1;
        }

        for (int ti = 0; ti < 32; ++ti) {
            T[ti] ^= U[ti];
        }
    }

    ft_memcpy(key, T, 16);

    return 0;
}


int gen_key(uint8_t *key, const char *password, const uint8_t *salt) {
    return pbkdf2_sha256(key, (const uint8_t *)password, ft_strlen(password), salt);
}
