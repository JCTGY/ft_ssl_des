/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/28 17:14:02 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/08 15:41:18 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dst, const void *src, int c, size_t n)
{
	unsigned char	*s_dst;
	unsigned char	*s_src;
	size_t			i;

	i = 0;
	s_dst = (unsigned char *)dst;
	s_src = (unsigned char *)src;
	if (n == 0 || dst == src)
		return (0);
	while (i < n)
	{
		s_dst[i] = s_src[i];
		if (s_src[i] == (unsigned char)c)
			return (s_dst + i + 1);
		i++;
	}
	return (0);
}
