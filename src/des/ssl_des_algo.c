/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_algo.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/22 20:15:46 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/08 22:31:28 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_des.h"
#include "ft_ssl.h"

static uint64_t			ssl_block(char *s)
{
	uint64_t		r;
	int				i;

	i = -1;
	r = 0;
	while (++i < 8)
	{
		r <<= 8;
		r += s[i];
	}
	return (r);
}

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

static int			ssl_des_enco(uint64_t msg, uint64_t ks[16], t_ba64 *ba, int b)
{
	uint64_t	tmp;
	uint64_t	l;
	uint64_t	r0;
	uint64_t	r;
	char		c;
	int			i;

	tmp = ssl_des_bit(msg, 64, g_des_ip1);
	l = (tmp >> 32) & 0xFFFFFFFF;
	r0 = tmp  & 0xFFFFFFFF;
	i = -1;
	while (++i < 16)
	{
		tmp = ssl_des_sbox(ssl_expand(r0) ^ ks[i]);
		r = l ^ ssl_des_bit(tmp, 32, g_des_permu);
		l = r0;
		r0 = r;
	}
	r = ssl_des_bit((r << 32) + l, 64, g_des_ip2);
	i = -1;
	while (++i < 8)
	{
		c = (r >> (56 - (i * 8))) & 0xFF;
		ba->data[i + b] = c;
	}
	return (0);
}

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
	else
		ba->len = ft_strlen(ba->msg) - 16;
}

int				ssl_des_algo(t_ba64 *ba)
{
	t_key		k;
	int			i;
	int			len;
	uint64_t	sk[16];
	uint64_t	msg;

	ft_bzero(&k, sizeof(k));
	if (ba->key && !ba->iv)
	{
		ft_putstr("iv undefined\n");
		return (0);
	}
	ssl_generate_key(ba, &k);
	ssl_padding(ba, &k, ft_strlen(ba->msg));
	ssl_shift_key(ba, &k, sk);
	len = ft_strlen(k.msg);
	ba->data = (char *)ft_memalloc(sizeof(char) * len + 1);
	i = 0;
	while (i < len)
	{
		msg = ssl_block(k.msg + i);
		ssl_des_enco(msg, sk, ba, i);
		i += 8;
	}
	return (1);
}
