/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_get_key.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/04 17:58:04 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/21 20:04:07 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

static void			ssl_one_key_help(t_ba64 *ba, t_key *k, t_ssl ssl)
{
	if (!(ba->ct & DES_TR))
	{
		ft_memcpy(k->key, &ssl.md5[0], sizeof(ssl.md5[0]));
		ft_memcpy(k->iv, &ssl.md5[1], sizeof(ssl.md5[1]));
	}
	else
	{
		ft_memcpy(k->k1, &ssl.md5[0], sizeof(ssl.md5[0]));
		ft_memcpy(k->k2, &ssl.md5[1], sizeof(ssl.md5[1]));
	}
}

static void			ssl_one_key(t_ba64 *ba, t_key *k)
{
	t_ssl		ssl;
	size_t		len;
	uint8_t		*temp;

	ft_bzero(&ssl, sizeof(ssl));
	ssl.p_flg |= SSL_DES;
	len = ((ba->aoe != BA64_D && !ba->key) ||
			!(ft_strncmp((char *)ba->msg, "Salted__", 8)))
			? ft_strlen(ba->skey) + 8 : ft_strlen(ba->skey);
	temp = ft_memalloc(sizeof(*temp) * len + 1);
	ft_memcpy(temp, ba->skey, 8);
	if ((ba->aoe != BA64_D && !ba->key) ||
			!(ft_strncmp((char *)ba->msg, "Salted__", 8)))
		ft_memcpy(temp + ft_strlen(ba->skey), k->salt, 8);
	ssl_md5_init((uint8_t *)temp, len, &ssl);
	ssl_one_key_help(ba, k, ssl);
	ft_memdel((void *)&temp);
}

static void			ssl_tri_key(t_ba64 *ba, t_key *k)
{
	t_ssl		ssl;
	int			b;
	uint8_t		*temp;

	ft_bzero(&ssl, sizeof(ssl));
	ssl.p_flg |= SSL_DES;
	ssl_one_key(ba, k);
	temp = ft_memalloc(sizeof(uint8_t) * (16 + ft_strlen(ba->skey)) + 1);
	b = ssl_hex_to_char(ba, temp, k);
	ssl_md5_init(temp, b, &ssl);
	ft_memcpy(k->k3, &ssl.md5[0], sizeof(ssl.md5[0]));
	ft_memcpy(k->iv, &ssl.md5[1], sizeof(ssl.md5[1]));
	ft_memdel((void *)&temp);
}

static void			calculate_key(t_ba64 *ba, t_key *k)
{
	if (ba->key)
	{
		ssl_hex_to_by((uint8_t *)ba->key, k, I_KEY);
		ssl_hex_to_by((uint8_t *)ba->iv, k, I_IV);
	}
	else if (!(ba->ct & DES_TR))
		ssl_one_key(ba, k);
	else if (ba->ct & DES_TR)
	{
		k->k1 = ft_memalloc(sizeof(uint8_t) * 8 + 1);
		k->k2 = ft_memalloc(sizeof(uint8_t) * 8 + 1);
		k->k3 = ft_memalloc(sizeof(uint8_t) * 8 + 1);
		ssl_tri_key(ba, k);
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
