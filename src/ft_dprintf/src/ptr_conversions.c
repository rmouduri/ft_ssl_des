/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ptr_conversions.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: romain <rmouduri@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/30 21:49:40 by romain            #+#    #+#             */
/*   Updated: 2020/12/04 03:27:21 by romain           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>
#include "ft_dprintf.h"

static int	ft_put_ptr(int fd, unsigned long long n)
{
	char	*hex;

	hex = "0123456789abcdef";
	if (n >= 16)
		return (ft_put_ptr(fd, n / 16) + ft_putchar_ret(fd, hex[n % 16]));
	return (ft_putchar_ret(fd, hex[n % 16]));
}

static int	get_ptr_length(unsigned long long n, t_inf inf)
{
	int					size;
	unsigned long long	nb;

	nb = n;
	size = 3;
	while (nb >= 16)
	{
		nb /= 16;
		++size;
	}
	if (n == 0 && inf.form_dot && !inf.prec_dot)
		--size;
	else if (inf.form_dot && size > inf.prec_dot)
		return (inf.prec_dot);
	return (size);
}

int			ptr_conversions(int fd, t_inf inf, va_list val)
{
	void				*ptr;
	unsigned long long	uptr;
	int					ret;
	int					length;

	ret = 0;
	ptr = va_arg(val, void *);
	uptr = (unsigned long long)ptr;
	length = get_ptr_length(uptr, inf);
	if (inf.form_nb && inf.prec_nb > 0)
		while (inf.prec_nb-- > length)
			ret += write(fd, " ", 1);
	ret += write(fd, "0x", 2);
	if (!inf.form_dot || (inf.form_dot && inf.prec_dot && !uptr) ||
		(inf.form_dot && uptr))
		ret += ft_put_ptr(fd, uptr);
	if (inf.form_nb && inf.prec_nb < 0)
		while (inf.prec_nb++ < length * -1)
			ret += write(fd, " ", 1);
	return (ret);
}
