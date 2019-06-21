/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_help_2.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/15 11:06:54 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/20 22:10:09 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

void				ssl_hex_to_char(t_ba64 *ba, uint8_t *temp, t_key *k)
{
//	char	*key2;
	int		i;

	//key = ft_itoa_base(1, 16, 16, *(uint64_t*)k->k1);
	//key2 = ft_itoa_base(1, 16, 16, *(uint64_t*)k->k2);
	i = 0;
	ft_memcpy(temp, k->k1, 8);
	ft_memcpy(temp + 8, k->k2, 16);
	ft_memcpy(temp + 16, ba->skey, ft_strlen(ba->skey));
//	i += (16 + ft_strlen(ba->skey));
//	ft_memcpy(temp + i, k->salt, 8);
	//ft_strdel(&key);
	//ft_strdel(&key2);
	printf("baskey len  == %zu\n", ft_strlen(ba->skey));
	printf("key itoa == %016llX\n", *(uint64_t*)(temp));
	printf("key itoa == %016llX\n", *(uint64_t*)(temp + 8));
	printf("key itoa == %016llX\n", *(uint64_t*)(temp + 16));
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
