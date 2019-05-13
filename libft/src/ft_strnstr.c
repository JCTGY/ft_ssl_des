/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/12 15:45:42 by jchiang-          #+#    #+#             */
/*   Updated: 2019/03/28 10:56:11 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *str, const char *src, size_t n)
{
	size_t		i;
	size_t		j;
	size_t		len;

	i = 0;
	if (!src[0])
		return ((char *)&str[i]);
	len = ft_strlen(src);
	while (str[i] != '\0')
	{
		if (i + len > n)
			return (0);
		j = 0;
		while (str[i + j] == src[j] && src[j] != '\0')
		{
			if (src[j + 1] == '\0')
				return ((char *)&str[i]);
			j++;
		}
		i++;
	}
	return (0);
}
