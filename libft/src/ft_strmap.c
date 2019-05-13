/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/04 16:27:37 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/12 19:00:16 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmap(const char *s, char (*f)(char))
{
	char	*new_s;
	size_t	i;

	if (!s || !f)
		return (0);
	new_s = ft_strnew(ft_strlen(s));
	if (!new_s)
		return (0);
	i = 0;
	while (s[i] != '\0')
	{
		new_s[i] = f(s[i]);
		i++;
	}
	return (new_s);
}
