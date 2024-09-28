/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: romain <rmouduri@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/26 18:52:09 by romain            #+#    #+#             */
/*   Updated: 2020/12/07 14:07:44 by romain           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>
#include "ft_dprintf.h"

static int	n_conversion(va_list val, int printed_chars)
{
	int	*n;

	if ((n = va_arg(val, int *)))
		n = &printed_chars;
	return (0);
}

static int	select_func(va_list val, t_inf inf, int printed_chars, int fd)
{
	int		i;
	char	*conversions;
	int		(*func[8])(int, t_inf, va_list);

	if (inf.conversion == '%')
		return (percent_conversion(fd, inf));
	if (inf.conversion == 'n')
		return (n_conversion(val, printed_chars));
	i = -1;
	conversions = "cspdiuxX";
	func[0] = &char_conversions;
	func[1] = &char_conversions;
	func[2] = &ptr_conversions;
	func[3] = &int_conversions;
	func[4] = &int_conversions;
	func[5] = &uint_conversions;
	func[6] = &uint_conversions;
	func[7] = &uint_conversions;
	while (conversions[++i])
		if (inf.conversion == conversions[i])
			return ((*func[i])(fd, inf, val));
	return (0);
}

static int	print_all(const int fd, const char *s, va_list val)
{
	t_inf		infos;
	int			printed_chars;
	int			i;

	printed_chars = 0;
	i = -1;
	while (s[++i])
	{
		if (s[i] == '%')
		{
			++i;
			infos = get_infos(&s[i], val);
			printed_chars += select_func(val, infos, printed_chars, fd);
			while (s[i] && !is_conversion(s[i]))
				++i;
		}
		else
			printed_chars += write(fd, &s[i], 1);
		if (!s[i])
			return (printed_chars);
	}
	return (printed_chars);
}

int			ft_dprintf(int fd, const char *s, ...)
{
	va_list	val;
	int		ret;

	va_start(val, s);
	ret = print_all(fd, s, val);
	va_end(val);
	return (ret);
}
