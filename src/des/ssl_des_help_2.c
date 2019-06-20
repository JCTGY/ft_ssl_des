/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_help_2.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/15 11:06:54 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/20 12:34:07 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

void				ssl_hex_to_char(uint8_t *temp, t_key *k)
{
	char	*key;
	char	*key2;

	key = ft_itoa_base(1, 16, 16, *(uint64_t*)k->k1);
	key2 = ft_itoa_base(1, 16, 16, *(uint64_t*)k->k2);
	ft_memcpy(temp, key, 16);
	ft_memcpy(temp + 16, key2, 16);
	ft_strdel(&key);
	ft_strdel(&key2);
	printf("key itoa == %s\n", temp);
}

void				ssl_allocate_k(t_key *k)
{
	k->key = ft_memalloc(sizeof(uint8_t) * 8 + 1);
	k->salt = ft_memalloc(sizeof(uint8_t) * 8 + 1);
	k->iv = ft_memalloc(sizeof(uint8_t) * 8 + 1);
}

uint64_t			ssl_block(char *s)
{
	uint64_t		r;
	int				i;

	i = -1;
	r = 0;
	while (++i < 8)
	{
		r <<= 8;
		r += (uint8_t)s[i];
	}
	return (r);
}
