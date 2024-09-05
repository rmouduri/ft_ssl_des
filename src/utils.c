#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "ft_ssl.h"


void	*ft_memcpy(void *dest, const void *src, size_t n) {
	size_t				i;
	unsigned char		*destcpy;
	const unsigned char	*srccpy;

	destcpy = dest;
	srccpy = src;
	i = -1;
	while (++i < n)
		destcpy[i] = srccpy[i];
	return (dest);
}

void	*ft_memset(void *s, int c, size_t n) {
	size_t			i;
	unsigned char	*scpy;

	scpy = s;
	i = -1;
	while (++i < n)
		scpy[i] = (unsigned char)c;
	return (s);
}

int	ft_strcmp(const char *s1, const char *s2) {
	size_t	i;

	i = 0;
	while ((unsigned char)s1[i] && (unsigned char)s2[i] &&
		(unsigned char)s1[i] == (unsigned char)s2[i])
		++i;
	return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

static void free_ssl_inputs(ssl_input_t *ssl_inputs) {
    ssl_input_t *tmp;

    while (ssl_inputs) {
        tmp = ssl_inputs;
        ssl_inputs = ssl_inputs->next;

        if (tmp->type != ARG_INPUT && tmp->ssl_str) {
            free(tmp->ssl_str);
        }

        if (tmp->hash) {
            free(tmp->hash);
        }

        free(tmp);
    }
}

void free_ssl(ssl_t *ssl) {
	free_ssl_inputs(ssl->ssl_inputs);

	if (ssl->fd != -1 && ssl->fd != STDIN_FILENO) {
		close(ssl->fd);
	}
}