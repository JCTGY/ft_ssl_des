/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strndup.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/04 16:46:14 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/10 15:01:03 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strndup(const char *s1, size_t n)
{
	char	*new_s1;

	if (!(new_s1 = ft_strnew(n)))
		return (0);
	ft_strncpy(new_s1, s1, n);
	return (new_s1);
}
