/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   uint_conversions.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: romain <rmouduri@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/12/03 16:42:45 by romain            #+#    #+#             */
/*   Updated: 2020/12/08 16:03:37 by romain           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>
#include "ft_dprintf.h"

static int	get_uint_size(unsigned int n, unsigned int base, char conv)
{
	int	size;

	if (conv == 'X' || conv == 'x')
		base = 16;
	else if (conv == 'o')
		base = 8;
	size = 1;
	while (n >= base)
	{
		n /= base;
		++size;
	}
	return (size);
}

int			uint_conversions(int fd, t_inf inf, va_list val)
{
	int					ret;
	unsigned int		n;

	n = (unsigned int)va_arg(val, unsigned int);
	if (n == 0)
		return (write_int_zero(fd, inf));
	ret = get_uint_size(n, 10, inf.conversion);
	if (inf.form_zero && !inf.form_dot)
		ret += write_zero_flag(fd, inf, ret, 1);
	else
		ret += int_write_preflag(fd, inf, ret + (inf.form_hash ?
										2 : 0), 1);
	ft_put_uint_base(fd, n, 10, inf.conversion);
	ret += int_write_postflag(fd, inf, ret, 1);
	return (ret);
}
