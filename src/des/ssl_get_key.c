/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_get_key.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/04 17:58:04 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/11 20:47:57 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

static void			des_half_key(uint64_t kh[16], uint64_t k0)
{
	int			i;
	uint64_t	add;
	uint64_t	temp;
	uint64_t	s;

	i = -1;
	s = k0;
	while (++i < 16)
	{
		add = s >> (28 - g_left_shift[i]);
		temp = s << g_left_shift[i];
		temp += add;
		temp = temp & 0xFFFFFFF;
		s = temp;
		kh[i] = temp;
	}
}

static uint64_t		des_pc1(uint64_t k)
{
	int			i;
	uint64_t	tmp;
	uint64_t	r;

	i = -1;
	r = 0;
	while (++i < 56)
	{
		tmp = (k >> (64 - g_des_pc1[i])) & 1;
		r <<= 1;
		r += tmp;
	}
	r <<= 8;
	return (r);
}

int					ssl_shift_key(t_ba64 *ba, t_key *k, uint64_t sk[16])
{
	uint64_t	temp;
	uint64_t	r;
	uint64_t	kc[16];
	uint64_t	kd[16];
	int			d;
	int			i;
	int			b;

	i = -1;
	temp = (*(uint64_t *)k->key);
	printf("temp == %llx\n", temp);
	temp = des_pc1(temp);
	des_half_key(kc, (temp >> 36) & 0xFFFFFFF);
	des_half_key(kd, (temp >> 8) & 0xFFFFFFF);
	while (++i < 16)
	{
		d = (ba->aoe == BA64_D) ? 15 - i : i;
		temp = (kc[i] << 28) + kd[i];
		r = 0;
		b = -1;
		while (++b < 48)
		{
			r <<= 1;
			r += ((temp >> (56 - g_des_pc2[b])) & 1);
		}
		sk[d] = r;
	}
	return (0);
}

static void			calculate_key(t_ba64 *ba, t_key *k)
{
	t_ssl		ssl;
	size_t		len;
	char		*temp;

	ft_bzero(&ssl, sizeof(ssl));
	if (ba->key)
	{
		ssl_hex_to_by((uint8_t *)ba->key, k, I_KEY);
		ssl_hex_to_by((uint8_t *)ba->iv, k, I_IV);
	}
	else
	{
		ssl.p_flg |= SSL_DES;
		len = ((ba->aoe != BA64_D && !ba->key) || !(ft_strncmp(ba->msg, "Salted__", 8)))
				? ft_strlen(ba->skey) + 8 : ft_strlen(ba->skey);
		temp = ft_strnew(len);
		ft_strcpy(temp, ba->skey);
		if ((ba->aoe != BA64_D && !ba->key) || !(ft_strncmp(ba->msg, "Salted__", 8)))
			ft_memcpy(temp + ft_strlen(ba->skey), k->salt, 8);
		ssl_md5_init((uint8_t *)temp, len, &ssl);
		ft_memcpy(k->key, &ssl.md5[0], sizeof(ssl.md5[0]));
		ft_memcpy(k->iv, &ssl.md5[1], sizeof(ssl.md5[1]));
		ft_strdel(&temp);
	}
}
	
int					ssl_generate_key(t_ba64 *ba, t_key *k)
{
	if (!ba->salt && (ba->aoe == BA64_E || !ba->aoe) && !ba->key)
		getentropy(k->salt, 8);
	else if (ba->salt && (ba->aoe == BA64_E || !ba->aoe))
		ssl_hex_to_by((uint8_t *)ba->salt, k, I_SALT);
	else if (ba->aoe == BA64_D)
		decode_salt(ba, k);
	calculate_key(ba, k);
	return (0);
}
