/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/29 12:36:09 by jchiang-          #+#    #+#             */
/*   Updated: 2018/11/29 13:40:11 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memchr(const void *s, int c, size_t n)
{
	unsigned char	*b;
	size_t			i;

	i = 0;
	b = (unsigned char *)s;
	if (n == 0)
		return (0);
	while (i < n)
	{
		if (b[i] == (unsigned char)c)
			return ((void*)b + i);
		i++;
	}
	return (0);
}
