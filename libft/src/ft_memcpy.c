/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/28 16:05:38 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/08 14:24:59 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	unsigned char	*s_dst;
	unsigned char	*s_src;

	s_dst = (unsigned char *)dst;
	s_src = (unsigned char *)src;
	while (n--)
		*s_dst++ = *s_src++;
	return ((void*)dst);
}
