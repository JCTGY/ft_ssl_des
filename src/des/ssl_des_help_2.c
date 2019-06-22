/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_help_2.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/15 11:06:54 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/21 20:06:00 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"
#include "ft_sha512.h"

static void			ssl_des_change_ende_help(t_ba64 *ba, t_key *k)
{
	if (ba->ct & DES_TR2)
	{
		ba->ct ^= DES_TR2;
		ba->ct |= DES_TR3;
		ft_memset(k->key, 0, 8);
		ft_memcpy(k->key, k->k2, 8);
	}
	if (ba->aoe != BA64_D)
		ba->aoe = BA64_D;
	else if (ba->aoe == BA64_D)
		ba->aoe = BA64_E;
}

void				ssl_des_change_ende(t_ba64 *ba, t_key *k)
{
	if (ba->ct & DES_TR1)
	{
		ba->ct ^= DES_TR1;
		ba->ct |= DES_TR2;
		ft_memset(k->key, 0, 8);
		if (ba->aoe != BA64_D)
			ft_memcpy(k->key, k->k1, 8);
		else
			ft_memcpy(k->key, k->k3, 8);
	}
	else if (ba->ct & DES_TR2)
		ssl_des_change_ende_help(ba, k);
	else if (ba->ct & DES_TR3)
	{
		ba->ct ^= DES_TR3;
		ba->ct |= DES_TR1;
		ft_memset(k->key, 0, 8);
		if (ba->aoe == BA64_D)
			ft_memcpy(k->key, k->k3, 8);
		else
			ft_memcpy(k->key, k->k1, 8);
		ssl_des_change_ende_help(ba, k);
	}
}

int					ssl_hex_to_char(t_ba64 *ba, uint8_t *temp, t_key *k)
{
	uint64_t	tmp;
	int			i;

	i = 0;
	tmp = swap_64bit(*(uint64_t*)k->k1);
	ft_memcpy(temp, &tmp, 8);
	tmp = swap_64bit(*(uint64_t*)k->k2);
	ft_memcpy(temp + 8, &tmp, 8);
	ft_memcpy(temp + 16, ba->skey, ft_strlen(ba->skey));
	i += (16 + ft_strlen(ba->skey));
	if (!ft_strncmp((char *)ba->msg, "Salted__", 8) || (!ba->key && ba->aoe != BA64_D))
	{
		ft_memcpy(temp + i, k->salt, 8);
		i += 8;
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
