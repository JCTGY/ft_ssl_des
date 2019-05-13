/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pr_double.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/22 15:59:48 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/27 13:01:59 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include "libft.h"

static int		spcae_float(t_printf *p, int len)
{
	int		space;

	space = 0;
	if (p->wid && p->wid > (len + p->pre))
		space = p->wid - (len + p->pre);
	if ((p->pre || p->flg & F_H) && space)
		space = space - 1;
	return (space);
}

static void		float_itoa(t_printf *p, long decimal)
{
	char	*str;
	int		len;
	int		i;
	int		str_len;

	len = ft_count_digit(decimal, 10);
	str = ft_strnew(len);
	i = len;
	while (--i >= 0)
	{
		str[i] = decimal % 10 + '0';
		decimal = decimal / 10;
	}
	if (len >= 2)
		str[len - 2] = (str[len - 1] > '5') ? str[len - 2] + 1 : str[len - 2];
	str[len - 1] = '\0';
	str_len = ft_strlen(str);
	(str_len < p->pre) && ft_putnchar(p->pre - str_len, '0');
	ft_putnstr(str, p->pre);
	ft_strdel(&str);
}

int				printf_double(t_printf *p, long double nb)
{
	double		decimal;
	int			len;
	int			space;
	double		neg;
	long		in;

	in = (nb < 0) ? -nb : nb;
	p->pre = (!p->pre && !(p->flg & F_D)) ? 6 : p->pre;
	len = ft_count_digit(in, 10);
	len = (nb < 0 || (p->flg & F_P) || (p->flg & F_S)) ? len + 1 : len;
	neg = (nb < 0.0f) ? -nb : nb;
	decimal = (neg - in) * ft_int_pow(10, p->pre + 1);
	space = spcae_float(p, len);
	(!(p->flg & F_N) && !(p->flg & F_Z) && ft_putnchar(space, ' '));
	(nb < 0) && ft_putchar('-');
	(nb >= 0 && (p->flg & F_P)) && ft_putchar('+');
	(nb >= 0 && (p->flg & F_S) && !(p->flg & F_P)) && ft_putchar(' ');
	(p->flg & F_Z) && ft_putnchar(space, '0');
	(!p->pre && (neg - in) * 10 > 5)
		? ft_putuintmax(in + 1) : ft_putuintmax(in);
	(p->flg & F_H || p->pre) && ft_putchar('.');
	float_itoa(p, decimal);
	p->len += (p->pre || p->flg & F_H)
		? (space + p->pre + len + 1) : (space + len);
	return (0);
}
