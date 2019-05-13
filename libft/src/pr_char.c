/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pr_char.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/27 15:26:39 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/22 10:52:04 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include "ft_printf.h"

static int		w_count_space(int len, t_printf *p)
{
	int		space;

	space = 0;
	len = (p->pre && len != 0) ? p->pre : len;
	if (p->wid && p->wid > len)
		space = p->wid - len;
	return (space);
}

int				check_mod(t_printf *p)
{
	int		len;
	int		space;

	while (*p->format == ' ')
		p->format++;
	if (*p->format != '%')
		return (0);
	len = 1;
	space = w_count_space(len, p);
	!(p->flg & F_N) && ft_putnchar(space, ' ');
	ft_putchar('%');
	(p->flg & F_N) && ft_putnchar(space, ' ');
	p->len += (p->wid > len) ? p->wid : len;
	return (1);
}

int				printf_string(t_printf *p)
{
	char	*str;
	int		len;
	int		space;

	if (p->flg & F_P || p->flg & F_Z || p->flg & F_H
			|| p->flg & F_S)
		return (0);
	if (!p->pre && !p->wid && p->flg & F_D)
		return (0);
	str = va_arg(p->va, char *);
	p->len += (!str) ? 6 : 0;
	len = (!str) ? 0 : ft_strlen(str);
	space = w_count_space(len, p);
	(!(p->flg & F_N)) && ft_putnchar(space, ' ');
	if (str)
		(!p->pre) ? ft_putstr(str) : ft_putnstr(str, p->pre);
	else
		ft_putstr("(null)");
	(p->flg & F_N) && ft_putnchar(space, ' ');
	len = (p->pre && len != 0) ? p->pre : len;
	p->len += (p->wid > len) ? p->wid : len;
	return (1);
}

int				printf_character(t_printf *p)
{
	char	c;
	int		space;
	int		len;

	if (p->flg & F_P || p->flg & F_Z || p->flg & F_H)
		return (0);
	len = 1;
	c = va_arg(p->va, int);
	space = w_count_space(len, p);
	!(p->flg & F_N) && ft_putnchar(space, ' ');
	ft_putchar(c);
	(p->flg & F_N) && ft_putnchar(space, ' ');
	p->len += (p->wid > len) ? p->wid : len;
	return (1);
}
