#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "ft_ssl.h"
#include "base64.h"


static int8_t base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// static bool is_base64_char(char c) {
//     return (c >= 'A' && c <= 'Z') || 
//            (c >= 'a' && c <= 'z') || 
//            (c >= '0' && c <= '9') || 
//            (c == '+') || (c == '/');
// }

// static bool is_valid_base64(const char *input, size_t input_len) {
//     if (input_len % 4 != 0) {
//         return false;
//     }

//     for (size_t i = 0; i < input_len; i++) {
//         if (i < input_len - 2) {
//             if (!is_base64_char(input[i])) {
//                 return false;
//             }
//         } else {
//             if (input[i] != '=' && !is_base64_char(input[i])) {
//                 return false;
//             }
//         }
//     }

//     return true;
// }

static void decode(const uint8_t *input, const size_t input_len, char *output) {
    uint8_t char_4set[4];
    size_t i = 0, output_index = 0;
    int padding = 0;

    while (i < input_len) {
        for (int j = 0; j < 4 && i < input_len; ++i, ++j) {
            if (input[i] == PADDING) {
                char_4set[j] = 0;
                padding++;
            } else {
                char_4set[j] = base64_char_value(input[i]);
            }
        }

        output[output_index++] = (char_4set[0] << 2) | (char_4set[1] >> 4);
        if (padding < 2) { output[output_index++] = (char_4set[1] << 4) | (char_4set[2] >> 2); }
        if (padding < 1) { output[output_index++] = (char_4set[2] << 6) | (char_4set[3]); }
    }

    output[output_index] = 0;
}

static void encode(const uint8_t *input, const size_t input_len, char *output) {
    const uint8_t base64_chars[] = BASE64_CHARS;
    uint8_t char_3set[3] = {0};
    size_t i = 0, output_index = 0;

    while (i < input_len) {
        char_3set[i % 3] = input[i];
        if ((i + 1) % 3 == 0) {
            output[output_index++] = base64_chars[char_3set[0] >> 2];
            output[output_index++] = base64_chars[((char_3set[0] & 0b00000011) << 4) | ((char_3set[1] & 0b11110000) >> 4)];
            output[output_index++] = base64_chars[((char_3set[1] & 0b00001111) << 2) | ((char_3set[2] & 0b11000000) >> 6)];
            output[output_index++] = base64_chars[char_3set[2] & 0b00111111];

            for (int j = 0; j < 3; ++j) {
                char_3set[j] = 0;
            }
        }

        ++i;
    }

    if (i % 3) {
        output[output_index++] = base64_chars[(char_3set[0] >> 2)];
        output[output_index++] = base64_chars[(((char_3set[0] & 0b00000011) << 4) | ((char_3set[1] & 0b11110000) >> 4))];
        if (char_3set[1]) {
            output[output_index++] = base64_chars[((char_3set[1] & 0b00001111) << 2)];
            output[output_index++] = PADDING;
        } else {
            output[output_index++] = PADDING;
            output[output_index++] = PADDING;
        }
    }

    output[output_index] = 0;
}

char *get_input(const char *src, const size_t src_len, const ssl_base64_option_t options, size_t *input_len) {
    char *input = NULL;

    *input_len = src_len;
    if (options & DECODE_MODE_OPTION) {
        for (size_t i = 0; i < src_len; ++i) {
            if (src[i] == '\n') --(*input_len);
        }
    }

    if ((input = malloc(sizeof(char) * (*input_len + 1))) == NULL) {
        print_malloc_error("get_input");
        return NULL;
    }

    for (size_t srci = 0, i = 0; srci < src_len; ++srci) {
        if ((options & DECODE_MODE_OPTION) && src[srci] == '\n') continue;

        input[i++] = src[srci];
    }

    return input;
}

char *ft_base64(const char *og_input, const size_t og_input_len, const ssl_base64_option_t options, size_t *output_len) {
    size_t input_len = 0;
    char *input = get_input(og_input, og_input_len, options, &input_len);

    if (input == NULL) {
        print_malloc_error("ft_base64");
        return NULL;
    }

    *output_len = options & DECODE_MODE_OPTION
        ? ((input_len / 4) * 3) - ((input[input_len - 1] == PADDING) + (input[input_len - 2] == PADDING))
        : (4 * ((input_len + 2) / 3));
    char *output = malloc(sizeof(char) * (*output_len + 1));

    if (output == NULL) {
        print_malloc_error("ft_base64");
        free(input);
        return NULL;
    }

    ft_memset(output, 0, *output_len + 1);

    if (options & DECODE_MODE_OPTION) {
        decode((uint8_t *) input, input_len, output);
    } else {
        encode((uint8_t *) input, input_len, output);
    }

    free(input);
    return output;
}