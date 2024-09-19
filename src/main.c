#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ft_ssl.h"
#include "display.h"

int main(int argc, char **argv) {
    ssl_t   ssl = {
        .algo = -1,
        .options = 0,
        .fd = STDIN_FILENO,
        .ssl_inputs = NULL,
        .message = NULL,
        .message_len = 0,
        .key = NULL,
        .password = NULL,
        .salt = NULL,
        .init_vector = NULL
    };

    if (check_args(argc, argv, &ssl) == -1) {
        return 1;
    }

    uint8_t *(*hash_fun_ptr[2])(const uint8_t *, const size_t) = {
        &ft_md5,
        &ft_sha256
    };

    if (ssl.algo == MD5 || ssl.algo == SHA256) {
        ssl_input_t *tmp = ssl.ssl_inputs;
        while (tmp) {
            if (tmp->ssl_str || (!tmp->ssl_str && !tmp->len)) {
                if ((tmp->hash = hash_fun_ptr[ssl.algo](tmp->ssl_str, tmp->len)) == NULL) {
                    tmp = tmp->next;
                    continue;
                }
            }

            display(tmp, ssl.algo, ssl.options, ssl.fd);
            tmp = tmp->next;
        }
    } else if (ssl.algo == BASE64) {
        char *output = ft_base64(ssl.message, ssl.message_len, ssl.options);

        if (output) {
            ft_dprintf(ssl.fd, "%s", output);
            free(output);
        }
    } else if (ssl.algo == DES || ssl.algo == DES_ECB || ssl.algo == DES_CBC) {
        ft_des(&ssl);
    }

    free_ssl(&ssl);
    return 0;
}