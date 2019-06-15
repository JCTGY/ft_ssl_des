/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_algo.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/22 20:15:46 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/15 16:54:14 by jchiang-         ###   ########.fr       */
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
	else if (!ft_strncmp((char *)ba->msg, "Salted__", 8)
			&& ba->aoe == BA64_D)
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

int				ssl_rm_padding(t_ba64 *ba, t_key *k)
{
	int		p;

	p = k->msg[ba->len - 1];
	ba->len -= p;
	ba->data[ba->len] = '\0';
	return (0);
}

static int		ssl_des_init(t_ba64 *ba, t_key *k)
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
		if ((ba->ct & DES_CB) && ba->aoe != BA64_D)
			msg ^= ba->last;
		ssl_des_enco(msg, sk, ba, m);
		if ((ba->ct & DES_CB) && ba->aoe == BA64_D)
			ba->last = msg;
		m += 8;
	}
//	(ba->aoe != BA64_D) && ssl_rm_padding(ba, k);
	return (1);
}

void			ssl_swap_wsalt(t_ba64 *ba, t_key *k)
{
	ft_memdel((void *)&ba->msg);
	ba->msg = ft_memalloc(sizeof(uint8_t) * (ba->len + 16) + 1);
	ft_memcpy(ba->msg, "Salted__", 8);
	ft_memcpy(ba->msg + 8, k->salt, 8);
	ft_memcpy(ba->msg + 16, ba->data, ba->len);
	ft_memdel((void *)&ba->data);
}

static void		ssl_trkey_init(t_ba64 *ba, t_key *k)
{
	if (ba->aoe != BA64_D)
	{
		ft_memcpy(k->key, k->k1, 8);
		ssl_des_init(ba, k);
		printf("what is the len == %zu\n", ba->len);
		ssl_swap_wsalt(ba, k);
		ba->aoe = BA64_D;
		ft_memset(k->key, 0, 8);
		ft_memcpy(k->key, k->k2, 8);
		ssl_des_init(ba, k);
		printf("what is the len == %zu\n", ba->len);
		ssl_swap_data(ba);
		ba->aoe = BA64_E;
		ft_memset(k->key, 0, 8);
		ft_memcpy(k->key, k->k3, 8);
		ssl_des_init(ba, k);
		printf("what is the len == %zu\n", ba->len);
	}
	else if (ba->aoe == BA64_D)
	{
		ft_memcpy(k->key, k->k3, 8);
		ssl_des_init(ba, k);
		printf("what is the len == %zu\n", ba->len);
		ssl_swap_data(ba);
		ba->aoe = BA64_E;
		ft_memset(k->key, 0, 8);
		ft_memcpy(k->key, k->k2, 8);
		ssl_des_init(ba, k);
		printf("what is the len == %zu\n", ba->len);
		ssl_swap_wsalt(ba, k);
		ba->aoe = BA64_D;
		ft_memset(k->key, 0, 8);
		ft_memcpy(k->key, k->k1, 8);
		ssl_des_init(ba, k);
	}
}

int				ssl_des_algo(t_ba64 *ba, t_key *k)
{
	if (ba->key && !ba->iv)
	{
		ft_putstr("iv undefined\n");
		return (0);
	}
	if (!ft_strcmp(ba->cmd, "des-cbc") || !ft_strcmp(ba->cmd, "des") ||
			!ft_strcmp(ba->cmd, "des3") || !ft_strcmp(ba->cmd, "des3-cbc"))
		ba->ct |= DES_CB;
	if (!ft_strcmp(ba->cmd, "des3") || !ft_strcmp(ba->cmd, "des3-ecb") ||
		!ft_strcmp(ba->cmd, "des3-cbc"))
		ba->ct |= DES_TR;
	ssl_allocate_k(k);
	ssl_generate_key(ba, k);
	if (!(ba->ct & DES_TR))
		ssl_des_init(ba, k);
	else if (ba->ct & DES_TR)
		ssl_trkey_init(ba, k);
	return (0);
}
