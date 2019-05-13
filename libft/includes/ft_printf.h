/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/15 17:48:20 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/27 12:15:53 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PRINTF_H
# define FT_PRINTF_H

# include <stdarg.h>
# include <stdio.h>
# include "libft.h"

# define NUM(x)	ft_isdigit(x)

/*
** Length field
*/
# define L_H	(1 << 0)
# define L_HH	(1 << 1)
# define L_LO	(1 << 2)
# define L_LLO	(1 << 3)
# define L_L	(1 << 4)
# define L_J	(1 << 5)
# define L_Z	(1 << 6)

/*
** Flags field
*/
# define F_P	(1 << 0)
# define F_N	(1 << 1)
# define F_Z 	(1 << 2)
# define F_H	(1 << 3)
# define F_D	(1 << 4)
# define F_S	(1 << 5)

/*
** conversion
*/
# define CN_C	(1 << 0)
# define CN_S	(1 << 1)
# define CN_P	(1 << 2)
# define CN_D	(1 << 3)
# define CN_I	(1 << 4)
# define CN_U	(1 << 5)
# define CN_UX	(1 << 6)
# define CN_LX	(1 << 7)
# define CN_F	(1 << 8)
# define CN_O	(1 << 9)
# define CN_UU	(1 << 10)

/*
** typedef struct		s_lf
** {
**	size_t			h;
**	size_t			i;
**	size_t			l;
**}					t_lf;
** p = positive; n = negative; z = zero; h = hash; f = front digit;
** d = dot; b = back number; s = space
**
** typedef struct		s_flag
** {
**	char			p;
**	char			n;
**	size_t			z;
**	char			h;
**	size_t			f;
**	char			d;
**	size_t			b;
**	char			s;
** }					t_flg;
** format = store the argument
** con = store conversion
** va = valist
** i = index of format
** len = charate of output
** flg = typed struct for flag
** lf = typed struct for lenth
*/
typedef struct		s_printf
{
	int				con;
	int				flg;
	int				lf;
	int				wid;
	int				pre;
	size_t			len;
	char			*format;
	va_list			va;
}					t_printf;

int					count_space(int len, int zero, t_printf *p);
int					count_digit(intmax_t nb, int base);
int					count_zero(int len, t_printf *p);
int					check_mod(t_printf *p);
int					pr_conversion(t_printf *p);
int					ft_printf(const char *format, ...);
int					pr_output(t_printf *p);
int					printf_string(t_printf *p);
int					printf_character(t_printf *p);
int					printf_integer(t_printf *p);
int					printf_nbr(intmax_t nb, t_printf *p);
int					printf_uninbr(uintmax_t nb, int base, t_printf *p);
int					printf_unsigned_int(t_printf *p, int base);
int					printf_double(t_printf *p, long double nb);
int					pr_wildcard(t_printf *p);

#endif
