/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/05 15:36:26 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/12 19:38:44 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	ft_word_count(const char *s, char c)
{
	size_t		len;
	size_t		i;

	len = 0;
	i = 0;
	while (s[i] != '\0')
	{
		while (s[i] == c)
			i++;
		if (s[i] != '\0' && s[i] != c)
			len++;
		while (s[i] != '\0' && s[i] != c)
			i++;
	}
	return (len);
}

static int	ft_word_len(const char *s, char c)
{
	size_t		len;
	size_t		i;

	i = 0;
	len = 0;
	while (s[i] == c)
		i++;
	while (s[i] != '\0' && s[i] != c)
	{
		i++;
		len++;
	}
	return (len);
}

char		**ft_strsplit(const char *s, char c)
{
	int		i;
	int		j;
	int		l;
	char	**new_s;

	if (!s || !(new_s = (char **)malloc(sizeof(*new_s) *
					(ft_word_count(s, c) + 1))))
		return (0);
	i = 0;
	j = 0;
	while (i < ft_word_count(s, c))
	{
		l = 0;
		if (!(new_s[i] = (char *)malloc(sizeof(**new_s) *
				(ft_word_len(&s[j], c) + 1))))
			new_s[i] = 0;
		while (s[j] == c)
			j++;
		while (s[j] != '\0' && s[j] != c)
			new_s[i][l++] = s[j++];
		new_s[i][l] = '\0';
		i++;
	}
	new_s[i] = 0;
	return (new_s);
}
