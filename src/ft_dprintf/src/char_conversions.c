/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   char_conversions.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: romain <rmouduri@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/26 22:49:16 by romain            #+#    #+#             */
/*   Updated: 2020/12/04 03:27:37 by romain           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdarg.h>
#include <unistd.h>
#include "ft_dprintf.h"

int	write_char(int fd, t_inf inf, va_list val)
{
	int				ret;
	unsigned char	c;

	ret = 0;
	while (inf.form_nb && inf.prec_nb > 0 && inf.prec_nb-- > 1)
		ret += write(fd, " ", 1);
	c = inf.conversion == '%' ? '%' : (unsigned char)va_arg(val, int);
	ret += ft_putchar_ret(fd, c);
	while (inf.form_nb && inf.prec_nb++ < -1)
		ret += write(fd, " ", 1);
	return (ret);
}

int	char_conversions(int fd, t_inf inf, va_list val)
{
	int				ret;
	int				to_write;
	char			*s;

	ret = 0;
	if (inf.conversion == 'c')
		ret += write_char(fd, inf, val);
	else if (inf.conversion == 's')
	{
		if ((s = (char *)va_arg(val, char *)) == NULL || ft_strlen(s) == 0)
		{
			if (inf.prec_nb > 0)
				to_write = inf.form_dot && inf.prec_dot < 6 ?
					inf.prec_nb - inf.prec_dot : inf.prec_nb - 6;
			else
				to_write = inf.form_dot && inf.prec_dot < 6 ?
					inf.prec_nb + inf.prec_dot : inf.prec_nb + 6;
			return (!s ? ft_putstr_null(fd, inf, to_write) : ft_putstr_empty(fd, inf));
		}
		to_write = inf.form_dot && inf.prec_dot < ft_strlen(s) ?
			inf.prec_dot : ft_strlen(s);
		ret += ft_putstr_ret(fd, inf, s, to_write);
	}
	return (ret);
}
