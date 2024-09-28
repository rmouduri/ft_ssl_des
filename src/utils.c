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

int	ft_strncmp(const char *s1, const char *s2, const size_t n) {
	size_t	i;

	i = 0;
	while ((unsigned char)s1[i] && (unsigned char)s2[i] &&
		(unsigned char)s1[i] == (unsigned char)s2[i] && i < n - 1)
		++i;
	return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

int	ft_memcmp(const void *s1, const void *s2, size_t n) {
	size_t				i;
	const unsigned char	*s1cpy;
	const unsigned char	*s2cpy;

	if (n == 0)
		return (0);
	i = 0;
	s1cpy = s1;
	s2cpy = s2;
	while ((unsigned char)s1cpy[i] == (unsigned char)s2cpy[i] && i < n - 1)
		++i;
	return ((unsigned char)s1cpy[i] - (unsigned char)s2cpy[i]);
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

	if (ssl->fd != -1 && ssl->fd != STDOUT_FILENO) {
		close(ssl->fd);
	}

	if (ssl->message) {
		free(ssl->message);
		ssl->message = NULL;
	}

	if (ssl->output) {
		free(ssl->output);
		ssl->output = NULL;
	}
}