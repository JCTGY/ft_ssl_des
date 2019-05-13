/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   printf.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/15 17:41:20 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/27 13:40:45 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include "libft.h"

static void		reset(t_printf *p)
{
	p->flg = 0;
	p->con = 0;
	p->lf = 0;
	p->wid = 0;
	p->pre = 0;
}

int				pr_wildcard(t_printf *p)
{
	p->wid = (*(p->format - 1) != '.' && *p->format == '*') ?
		va_arg(p->va, int) : p->wid;
	if (p->wid < 0)
	{
		p->lf |= F_N;
		p->wid = -p->wid;
	}
	p->pre = (*(p->format - 1) == '.' && *p->format == '*') ?
		va_arg(p->va, int) : p->pre;
	return (0);
}

int				ft_printf(const char *format, ...)
{
	t_printf	p;

	ft_bzero(&p, sizeof(p));
	va_start(p.va, format);
	p.format = (char *)format;
	while (*p.format)
	{
		reset(&p);
		if (*p.format == '%')
		{
			p.format++;
			if (!pr_conversion(&p))
				break ;
			else
				pr_output(&p);
		}
		else
		{
			ft_putchar(*p.format);
			p.len++;
		}
		p.format++;
	}
	va_end(p.va);
	return (p.len);
}
