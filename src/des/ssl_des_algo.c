/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_algo.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/22 20:15:46 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/15 10:53:33 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

static void		ssl_padding(t_ba64 *ba, t_key *k, size_t old)
{
	size_t		len;

	if (!ba->aoe || ba->aoe == BA64_E)
	{
		len = (old / 8 + 1) * 8;
		if (len == old)
			len += 8;
		ba->len = len;
		k->msg = ft_strnew(len);
		ft_memcpy(k->msg, ba->msg, old);
		ft_memset(k->msg + old, len - old, len - old);
	}
	else if (!ft_strncmp((char *)ba->msg, "Salted__", 8))
	{
		ba->len = ba->len - 16;
		k->msg = ft_strnew(ba->len);
		ft_memcpy(k->msg, ba->msg + 16, ba->len);
	}
	else
	{
		k->msg = ft_strnew(ba->len);
		ft_memcpy(k->msg, ba->msg, ba->len);
	}
}

static void		ssl_allocate_k(t_key *k)
{
	k->key = ft_memalloc(sizeof(uint8_t) * 8 + 1);
	k->salt = ft_memalloc(sizeof(uint8_t) * 8 + 1);
	k->iv = ft_memalloc(sizeof(uint8_t) * 8 + 1);
}

static int				ssl_des_init(t_ba64 *ba, t_key *k)
{
	size_t		m;
	uint64_t	sk[16];
	uint64_t	msg;

	ssl_padding(ba, k, ba->len);
	ssl_shift_key(ba, k, sk);
	if (ba->ct)
		ba->last = *(uint64_t *)k->iv;
	ba->data = (uint8_t *)ft_memalloc(sizeof(uint8_t) * ba->len + 1);
	m = 0;
	ba->ct |= (!m && ba->ct) ? DES_C1 : 0;
	while (m < ba->len)
	{
		msg = ssl_block(k->msg + m);
		if (ba->ct && ba->aoe != BA64_D)
			msg ^= ba->last;
		ssl_des_enco(msg, sk, ba, m);
		if (ba->ct && ba->aoe == BA64_D)
			ba->last = msg;
		m += 8;
	}
	return (1);
}

int				ssl_des_algo(t_ba64 *ba, t_key *k)
{
	if (ba->key && !ba->iv)
	{
		ft_putstr("iv undefined\n");
		return (0);
	}
	if (!ft_strcmp(ba->cmd, "des-cbc") || !ft_strcmp(ba->cmd, "des"))
		ba->ct |= DES_CB;
	ssl_allocate_k(k);
	ssl_generate_key(ba, k);
	ssl_des_init(ba, k);
	return (0);
}
