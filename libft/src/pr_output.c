/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pr_output.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/22 09:11:41 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/27 12:18:54 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include "libft.h"

int				pr_output(t_printf *p)
{
	if (!p->con)
		return (0);
	(p->con & CN_C) && printf_character(p);
	(p->con & CN_S) && printf_string(p);
	(p->con & CN_D || p->con & CN_I) && printf_integer(p);
	(p->con & CN_U) && printf_unsigned_int(p, 10);
	(p->con & CN_O) && printf_unsigned_int(p, 8);
	(p->con & CN_UX || p->con & CN_LX)
		&& printf_unsigned_int(p, 16);
	(p->con & CN_P) && (printf_uninbr((uintmax_t)
				va_arg(p->va, void *), 16, p));
	(p->con & CN_UU) && (printf_uninbr((uintmax_t)
				va_arg(p->va, unsigned long), 10, p));
	((p->con & CN_F) && (!(p->lf) || (p->lf & L_LO))) &&
		printf_double(p, va_arg(p->va, double));
	((p->con & CN_F) && (p->lf & L_L)) &&
		printf_double(p, va_arg(p->va, long double));
	return (1);
}
