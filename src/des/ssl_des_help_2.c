/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_help_2.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/15 11:06:54 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/21 10:24:46 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"
#include "ft_sha512.h"

int					ssl_hex_to_char(t_ba64 *ba, uint8_t *temp, t_key *k)
{
//	char	*key2;
	uint64_t	tmp;
	int			i;

	//key = ft_itoa_base(1, 16, 16, *(uint64_t*)k->k1);
	//key2 = ft_itoa_base(1, 16, 16, *(uint64_t*)k->k2);
	i = 0;
	tmp = swap_64bit(*(uint64_t*)k->k1);;
	ft_memcpy(temp, &tmp, 8);
	tmp = swap_64bit(*(uint64_t*)k->k2);;
	ft_memcpy(temp + 8, &tmp, 8);
	ft_memcpy(temp + 16, ba->skey, ft_strlen(ba->skey));
	i += (16 + ft_strlen(ba->skey));
	ft_memcpy(temp + i, k->salt, 8);
	i += 8;
	//ft_strdel(&key);
	//ft_strdel(&key2);
//	printf("key itoa == %016llX\n", *(uint64_t*)(temp));
//	printf("key itoa == %016llX\n", *(uint64_t*)(temp + 8));
//	printf("key itoa == %016llX\n", *(uint64_t*)(temp + 16));
	for (int x = 0; x < 24; x += 8){
		uint64_t r = 0;
		for (int y = 0; y < 8; y++){
			r <<= 8;
			r += temp[y + x];
		}
		printf("hex of the slated == %llx\n", r);
	}
	return (i);
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
