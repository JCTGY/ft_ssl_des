/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_count_digit.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/01 14:39:57 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/21 16:02:50 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int			ft_count_digit(uintmax_t nb, int base)
{
	int		len;

	len = 0;
	if (!nb)
		return (1);
	while (nb)
	{
		len++;
		nb = nb / base;
	}
	return (len);
}
