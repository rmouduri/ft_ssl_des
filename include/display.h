#ifndef _display_H_
# define _display_H

#define SSL_NO_FILE_DIRECTORY   "ft_ssl: md5: %s: No such file or directory\n"


void ft_hexdump(const void *ptr, int size, int fd);
void ft_binarydump(const void *ptr, int size, int fd);
void display(const ssl_input_t *input, ssl_encrypt_algo_t algo, ssl_option_t options, int fd);

#endif // _display_H_