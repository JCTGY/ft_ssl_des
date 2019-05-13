/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/04 17:16:22 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/05 15:20:49 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strsub(char const *s, unsigned int start, size_t len)
{
	char	*new_s;
	size_t	i;

	if (!s)
		return (0);
	new_s = ft_strnew(len);
	if (!new_s)
		return (0);
	i = 0;
	while (i < len)
	{
		new_s[i] = s[start];
		i++;
		start++;
	}
	return (new_s);
}
