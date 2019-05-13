/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/05 14:43:33 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/08 14:38:06 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strtrim(const char *s)
{
	size_t		i;
	size_t		d;

	i = 0;
	if (!s)
		return (0);
	while (s[i] == ' ' || s[i] == '\t' || s[i] == '\n')
		i++;
	if (s[i] == '\0')
		return (ft_strnew(0));
	d = ft_strlen(s);
	d--;
	while (s[d] == ' ' || s[d] == '\t' || s[d] == '\n')
		d--;
	d = d - i + 1;
	return (ft_strsub(s, i, d));
}
