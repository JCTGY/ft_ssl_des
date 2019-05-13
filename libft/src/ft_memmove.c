/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/29 11:38:46 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/12 13:56:32 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	char	*new_dst;
	char	*new_src;
	size_t	i;

	new_dst = (char *)dst;
	new_src = (char *)src;
	i = -1;
	if (new_src < new_dst)
		while ((int)--len >= 0)
			new_dst[len] = new_src[len];
	else
		while (++i < len)
			new_dst[i] = new_src[i];
	return (dst);
}
