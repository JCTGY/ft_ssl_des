/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/28 14:38:19 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/12 19:30:05 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t dstsize)
{
	size_t		i;
	size_t		d_len;
	size_t		s_len;

	d_len = ft_strlen(dst);
	s_len = ft_strlen(src);
	if (dstsize <= ft_strlen(dst) + 1)
		return (s_len + dstsize);
	i = 0;
	while (dst[i] != '\0' && i < dstsize - 1)
		i++;
	while (*src && i < dstsize - 1)
	{
		dst[i] = *src;
		i++;
		src++;
	}
	dst[i] = '\0';
	return (d_len + s_len);
}
