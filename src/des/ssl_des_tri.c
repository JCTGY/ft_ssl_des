/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_tri.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/21 15:35:25 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/21 21:24:15 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

static void		ssl_cbc_encode(uint64_t r, t_ba64 *ba, size_t b)
{
	char		c;
	int			i;

	if ((ba->ct & DES_CB) && ba->aoe == BA64_D)
		r ^= ba->last;
	i = -1;
	while (++i < 8)
	{
		c = (r >> (56 - (i * 8))) & 0xFF;
		ba->data[i + b] = c;
	}
	if ((ba->ct & DES_CB) && ba->aoe != BA64_D)
		ba->last = r;
}

static void		ssl_tri_cbc(t_ba64 *ba, t_key *k)
{
	size_t		m;
	uint64_t	r;
	uint64_t	sk[16];
	uint64_t	msg;

	m = 0;
	while (m < ba->len)
	{
		msg = ssl_block(k->msg + m);
		if ((ba->ct & DES_CB) && ba->aoe != BA64_D)
			msg ^= ba->last;
		ssl_des_change_ende(ba, k);
		ssl_shift_key(ba, k, sk);
		r = ssl_des_encode_help(msg, sk);
		ssl_des_change_ende(ba, k);
		ssl_shift_key(ba, k, sk);
		r = ssl_des_encode_help(r, sk);
		ssl_des_change_ende(ba, k);
		ssl_shift_key(ba, k, sk);
		r = ssl_des_encode_help(r, sk);
		ssl_cbc_encode(r, ba, m);
		if ((ba->ct & DES_CB) && ba->aoe == BA64_D)
			ba->last = msg;
		m += 8;
	}
}

static void		ssl_tri_dedes(t_ba64 *ba, t_key *k)
{
	ft_memcpy(k->key, k->k3, 8);
	ssl_des_init(ba, k);
	ssl_swap_wsalt(ba, k);
	ba->aoe = BA64_E;
	ft_memset(k->key, 0, 8);
	ft_memcpy(k->key, k->k2, 8);
	ssl_des_init(ba, k);
	ssl_swap_wsalt(ba, k);
	ba->aoe = BA64_D;
	ft_memset(k->key, 0, 8);
	ft_memcpy(k->key, k->k1, 8);
	ssl_des_init(ba, k);
}

static void		ssl_tri_endes(t_ba64 *ba, t_key *k)
{
	ft_memcpy(k->key, k->k1, 8);
	ssl_des_init(ba, k);
	ssl_swap_wsalt(ba, k);
	ba->aoe = BA64_D;
	ft_memset(k->key, 0, 8);
	ft_memcpy(k->key, k->k2, 8);
	ssl_des_init(ba, k);
	ssl_swap_wsalt(ba, k);
	ba->aoe = BA64_E;
	ft_memset(k->key, 0, 8);
	ft_memcpy(k->key, k->k3, 8);
	ssl_des_init(ba, k);
}

void			ssl_trkey_init(t_ba64 *ba, t_key *k)
{
	if (!(ba->ct & DES_CB))
	{
		if (ba->aoe != BA64_D)
			ssl_tri_endes(ba, k);
		else
			ssl_tri_dedes(ba, k);
	}
	else
	{
		ba->ct |= DES_TR1;
		ba->last = *(uint64_t *)k->iv;
		ba->data = (uint8_t *)ft_memalloc(sizeof(uint8_t) * ba->len + 1);
		ssl_tri_cbc(ba, k);
	}
	ft_memdel((void *)&k->k1);
	ft_memdel((void *)&k->k2);
	ft_memdel((void *)&k->k3);
}
