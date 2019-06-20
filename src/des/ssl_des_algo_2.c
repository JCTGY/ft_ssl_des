/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_algo_2.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/13 18:33:38 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/20 10:16:41 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

static uint64_t		ssl_des_sbox(uint64_t in)
{
	int			i;
	int			row;
	int			col;
	uint64_t	tmp;
	uint64_t	r;

	i = -1;
	r = 0;
	while (++i < 8)
	{
		tmp = (in >> (42 - (i * 6))) & 0x3F;
		col = (tmp >> 1) & 0xF;
		row = ((tmp >> 5) << 1) + (tmp & 1);
		tmp = g_s_boxes[i][row * 16 + col];
		r <<= 4;
		r += tmp;
	}
	return (r);
}

static uint64_t		ssl_expand(uint64_t in)
{
	uint64_t	r;
	uint64_t	tmp;
	int			i;

	i = -1;
	r = 0;
	while (++i < 48)
	{
		tmp = (in >> (32 - g_des_expan[i])) & 1;
		r <<= 1;
		r += tmp;
	}
	return (r);
}

static uint64_t		ssl_des_bit(uint64_t in, int n, const unsigned char *g)
{
	uint64_t	r;
	int			i;

	i = -1;
	r = 0;
	while (++i < n)
	{
		r <<= 1;
		r += (in >> (n - g[i])) & 1;
	}
	return (r);
}

static uint64_t		ssl_des_encode_help(uint64_t msg, uint64_t ks[16])
{
	uint64_t	tmp;
	uint64_t	l;
	uint64_t	r0;
	uint64_t	r;
	int			i;

	tmp = ssl_des_bit(msg, 64, g_des_ip1);
	l = (tmp >> 32) & 0xFFFFFFFF;
	r0 = tmp & 0xFFFFFFFF;
	i = -1;
	while (++i < 16)
	{
		tmp = ssl_des_sbox(ssl_expand(r0) ^ ks[i]);
		r = l ^ ssl_des_bit(tmp, 32, g_des_permu);
		l = r0;
		r0 = r;
	}
	r = ssl_des_bit((r << 32) + l, 64, g_des_ip2);
	return (r);
}

int					ssl_des_enco(uint64_t msg, uint64_t ks[16],
		t_ba64 *ba, size_t b)
{
	char		c;
	uint64_t	r;
	int			i;

	r = ssl_des_encode_help(msg, ks);
	if ((ba->ct & DES_CB) && ba->aoe == BA64_D)
	{
		ba->ct ^= DES_C1;
		r ^= ba->last;
	}
	i = -1;
	while (++i < 8)
	{
		c = (r >> (56 - (i * 8))) & 0xFF;
		ba->data[i + b] = c;
	}
	if ((ba->ct & DES_CB) && ba->aoe != BA64_D)
		ba->last = r;
	return (0);
}
