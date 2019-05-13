/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/27 15:37:01 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/13 19:34:45 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_atoi(const char *str)
{
	int		s;
	int		r;
	int		len;

	while (ft_isspace(*str))
		str++;
	s = (*str == '-') ? -1 : 1;
	(*str == '+' || *str == '-') ? str++ : str;
	r = 0;
	len = 0;
	while (ft_isdigit(str[len]))
		len++;
	if (len >= 19)
		return ((s > 0) ? -1 : 0);
	while (*str && ft_isdigit(*str))
		r = r * 10 + (*str++ - '0');
	return (r * s);
}
