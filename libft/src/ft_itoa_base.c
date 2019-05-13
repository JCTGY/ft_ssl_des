/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa_base.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/01 14:37:50 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/23 19:44:18 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_itoa_base(int c, int base, int len, uintmax_t nb)
{
	char	*b;
	char	*s;

	if (base < 2 || base > 16)
		return (0);
	s = ft_strnew(len);
	b = ft_strnew(16);
	(c == 1) ? (ft_strcpy(b, "0123456789ABCDEF"))
		: (ft_strcpy(b, "0123456789abcdef"));
	s[len] = '\0';
	while (--len >= 0)
	{
		s[len] = b[nb % base];
		nb = nb / base;
	}
	ft_strdel(&b);
	return (s);
}
