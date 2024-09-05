#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "ft_ssl.h"
#include "ft_md5.h"


static int MD5_Padding(const uint8_t *input, const size_t input_len, ft_md5_t *md5) {
    uint8_t *padded_input;

    md5->input_len = 64 + (64 * ((input_len / 64) + (input_len % 64 >= 56 ? 1 : 0)));
    padded_input = malloc(sizeof(uint8_t) * md5->input_len);

    if (padded_input == NULL) {
        print_malloc_error("MD5_Padding");
        return -1;
    }

    ft_memcpy(padded_input, input, input_len);
    ft_memset(padded_input + input_len, 0b10000000, 1);
    ft_memset(padded_input + input_len + 1, 0, md5->input_len - (input_len + 1));

    const uint64_t len_in_bits = input_len * 8;
    ft_memcpy(padded_input + (md5->input_len - 8), &len_in_bits, sizeof(uint64_t));

    md5->input = (uint32_t *) padded_input;
    return 0;
}

static void MD5_Algo(ft_md5_t *md5) {
    const uint32_t k[64] = K;
    const uint32_t r[64] = R;
    uint32_t tmp_state[4];
    uint32_t hash;
    uint8_t g;

    md5->state[A] = 0x67452301;
    md5->state[B] = 0xEFCDAB89;
    md5->state[C] = 0x98BADCFE;
    md5->state[D] = 0x10325476;

    for (uint64_t chunk_index = 0; chunk_index < md5->input_len; chunk_index += 64) {
        for (uint8_t state_index = A; state_index <= D; ++state_index) {
            tmp_state[state_index] = md5->state[state_index];
        }

        for (uint8_t i = 0; i < 64; ++i) {
            if (i < 16) {
                g = i;
                hash = tmp_state[A] + F(tmp_state[B], tmp_state[C], tmp_state[D]) + md5->input[(chunk_index / 4) + g];
            } else if (i < 32) {
                g = ((i * 5 + 1) % 16);
                hash = tmp_state[A] + G(tmp_state[B], tmp_state[C], tmp_state[D]) + md5->input[(chunk_index / 4) + g];
            } else if (i < 48) {
                g = ((i * 3 + 5) % 16);
                hash = tmp_state[A] + H(tmp_state[B], tmp_state[C], tmp_state[D]) + md5->input[(chunk_index / 4) + g];
            } else if (i < 64) {
                g = ((i * 7) % 16);
                hash = tmp_state[A] + I(tmp_state[B], tmp_state[C], tmp_state[D]) + md5->input[(chunk_index / 4) + g];
            }

            hash += k[i];
            hash = ROTATE_LEFT(hash, r[i]);
            hash += tmp_state[B];

            tmp_state[A] = tmp_state[D];
            tmp_state[D] = tmp_state[C];
            tmp_state[C] = tmp_state[B];
            tmp_state[B] = hash;
        }

        for (uint8_t state_index = A; state_index <= D; ++state_index) {
            md5->state[state_index] += tmp_state[state_index];
        }
    }
}

uint8_t *ft_md5(const uint8_t *input, const size_t input_len) {
    ft_md5_t    md5;
    uint8_t    *hash;

    if (MD5_Padding(input, input_len, &md5) == -1) {
        return NULL;
    }

    MD5_Algo(&md5);

    free(md5.input);

    if ((hash = malloc(sizeof(uint8_t) * 16)) == NULL) {
        print_malloc_error("ft_md5");
        return NULL;
    }

    ft_memcpy(hash, md5.state, sizeof(md5.state));
    return hash;
}