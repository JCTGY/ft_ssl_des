/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/04 17:24:59 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/08 14:37:33 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strjoin(char const *s1, char const *s2)
{
	char	*new_s;

	if (!s1 || !s2)
		return (0);
	new_s = ft_strnew(ft_strlen(s1) + ft_strlen(s2));
	if (!new_s)
		return (0);
	ft_strcpy(new_s, s1);
	ft_strcat(new_s, s2);
	return (new_s);
}
