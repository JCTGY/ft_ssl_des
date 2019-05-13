/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pr_uninteger.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/02 12:25:32 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/22 10:30:24 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include "libft.h"

static int		put_hash(t_printf *p, uintmax_t nb)
{
	(p->con & CN_UX && nb) ? ft_putstr("0X") : 0;
	(p->con & CN_LX && nb) ? ft_putstr("0x") : 0;
	(p->con & CN_P && nb) ? ft_putstr("0x") : 0;
	(p->con & CN_O) ? ft_putchar('0') : 0;
	return (0);
}

static int		count_hash(int len, t_printf *p, uintmax_t nb)
{
	if (!(p->con & CN_P) && !(p->con & CN_UX) &&
			!(p->con & CN_LX) && !(p->con & CN_O))
		return (0);
	if ((!(p->con & CN_O) && nb))
		len = len + 2;
	if (p->con & CN_O && nb)
		len = len + 1;
	return (len);
}

int				printf_uninbr(uintmax_t nb, int base, t_printf *p)
{
	int		c;
	int		space;
	int		len;
	int		zero;
	char	*str;

	str = NULL;
	c = (p->con & CN_UX) ? 1 : 0;
	len = ft_count_digit(nb, base);
	str = ft_itoa_base(c, base, len, nb);
	len = (p->flg & F_H || p->con & CN_P)
		? count_hash(len, p, nb) : len;
	if (!(p->con & CN_O) || !(p->flg & F_H))
		len = (p->flg & F_D && !nb) ? 0 : len;
	zero = count_zero(len, p);
	space = count_space(len, zero, p);
	p->len += (p->wid > (len + zero)) ? p->wid : (len + zero);
	(!(p->flg & F_N)) && ft_putnchar(space, ' ');
	(p->flg & F_H || p->con & CN_P) && put_hash(p, nb);
	ft_putnchar(zero, '0');
	(!(p->flg & F_D) || nb) ? ft_putstr(str) : 1;
	(p->flg & F_N) && ft_putnchar(space, ' ');
	ft_strdel(&str);
	return (0);
}

int				printf_unsigned_int(t_printf *p, int base)
{
	if (p->lf & L_L)
		return (0);
	(p->lf & L_LLO) && (printf_uninbr((unsigned long long)
				va_arg(p->va, unsigned long long int), base, p));
	(p->lf & L_LO) && (printf_uninbr((unsigned long)
				va_arg(p->va, unsigned long int), base, p));
	(p->lf & L_HH) && (printf_uninbr((unsigned char)
					va_arg(p->va, unsigned int), base, p));
	(p->lf & L_H) && (printf_uninbr((unsigned short)
					va_arg(p->va, unsigned int), base, p));
	(p->lf & L_J) && (printf_uninbr((uintmax_t)
					va_arg(p->va, uintmax_t), base, p));
	(p->lf & L_Z) && (printf_uninbr((uintmax_t)
				va_arg(p->va, size_t), base, p));
	(!p->lf) && (printf_uninbr((unsigned int)
				va_arg(p->va, unsigned int), base, p));
	return (1);
}
