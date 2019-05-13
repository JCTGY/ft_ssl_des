/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pr_verify.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/21 14:51:07 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/22 10:26:27 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include "libft.h"

/*
** check and save the flag
*/

static int		pr_flag(t_printf *p)
{
	if (*p->format != '+' && *p->format != '-' && *p->format != ' '	\
			&& *p->format != '0' && *p->format != '#')
		return (0);
	p->flg = (*p->format == '+') ? (p->flg |= F_P) : p->flg;
	p->flg = (*p->format == '-') ? (p->flg |= F_N) : p->flg;
	p->flg = (*p->format == '0') ? (p->flg |= F_Z) : p->flg;
	p->flg = (*p->format == '#') ? (p->flg |= F_H) : p->flg;
	p->flg = (*p->format == ' ') ? (p->flg |= F_S) : p->flg;
	return (1);
}

static int		pr_wid_pre(t_printf *p)
{
	size_t		i;
	char		*nb;

	i = 0;
	if (!(NUM(*p->format)) && *p->format != '.' && *p->format != '*')
		return (0);
	p->flg = (*p->format == '.') ? (p->flg |= F_D) : p->flg;
	while (NUM(p->format[i]))
		i++;
	if (NUM(*p->format) && !p->wid && (*(p->format - 1) != '.'))
	{
		if (!(nb = ft_strsub(p->format, 0, i)))
			return (0);
		p->wid = ft_atoi(nb);
		free(nb);
	}
	if (NUM(*p->format) && !p->pre && (*(p->format - 1) == '.'))
	{
		if (!(nb = ft_strsub(p->format, 0, i)))
			return (0);
		p->pre = ft_atoi(nb);
		free(nb);
	}
	(*p->format == '*') && pr_wildcard(p);
	return (1);
}

static int		pr_len_fl(t_printf *p)
{
	(p->lf & L_LLO || p->lf & L_HH) && p->format++;
	if (*p->format != 'h' && *p->format != 'l'
			&& *p->format != 'L' && *p->format != 'j' && *p->format != 'z')
		return (0);
	p->lf = ((*p->format == 'h') && *(p->format + 1) != 'h')
			? p->lf |= L_H : p->lf;
	p->lf = ((*p->format == 'h') && *(p->format + 1) == 'h')
			? p->lf |= L_HH : p->lf;
	p->lf = ((*p->format == 'l') && *(p->format + 1) != 'l')
			? p->lf |= L_LO : p->lf;
	p->lf = ((*p->format == 'l') && *(p->format + 1) == 'l')
			? p->lf |= L_LLO : p->lf;
	p->lf = (*p->format == 'L') ? p->lf |= L_L : p->lf;
	p->lf = (*p->format == 'j') ? p->lf |= L_J : p->lf;
	p->lf = (*p->format == 'z') ? p->lf |= L_Z : p->lf;
	return (1);
}

static int		pr_input_con(t_printf *p)
{
	if (!(ft_strchr("cspdiuxXfoiU", *p->format)))
		return (0);
	p->con = (*p->format == 'c') ? p->con |= CN_C : p->con;
	p->con = (*p->format == 's') ? p->con |= CN_S : p->con;
	p->con = (*p->format == 'p') ? p->con |= CN_P : p->con;
	p->con = (*p->format == 'd') ? p->con |= CN_D : p->con;
	p->con = (*p->format == 'i') ? p->con |= CN_I : p->con;
	p->con = (*p->format == 'u') ? p->con |= CN_U : p->con;
	p->con = (*p->format == 'f') ? p->con |= CN_F : p->con;
	p->con = (*p->format == 'o') ? p->con |= CN_O : p->con;
	p->con = (*p->format == 'X') ? p->con |= CN_UX : p->con;
	p->con = (*p->format == 'x') ? p->con |= CN_LX : p->con;
	p->con = (*p->format == 'U') ? p->con |= CN_UU : p->con;
	return (1);
}

int				pr_conversion(t_printf *p)
{
	while (pr_flag(p))
		p->format++;
	while (pr_wid_pre(p))
		p->format++;
	while (pr_len_fl(p))
		p->format++;
	if (!pr_input_con(p))
		return (check_mod(p));
	return (1);
}
