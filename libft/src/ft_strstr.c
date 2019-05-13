/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/27 16:13:36 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/12 19:30:59 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strstr(const char *str, const char *src)
{
	size_t		i;
	size_t		j;

	i = 0;
	if (!src[0])
		return ((char *)&str[i]);
	while (str[i] != '\0')
	{
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
