/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha512.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/29 18:24:23 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/29 19:44:59 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_sha512.h"

static void		sha512_print(t_sha512 *sha, t_ssl *ssl)
{
	if (ssl->flag & SSL_P)
	{
		(!(ssl->flag & SSL_PP)) && ft_printf("%s", ssl->name);
		sha512_print_help(sha);
		return ;
	}
	if (!(ssl->flag & SSL_R) && !(ssl->flag & SSL_ST) && !(ssl->flag & SSL_P))
	{
		(!(ssl->flag & SSL_Q) && (ssl->flag & SSL_S)) &&
			ft_printf("sha512(\"%s\")= ", ssl->name);
		(!(ssl->flag & SSL_Q) && !(ssl->flag & SSL_S)) &&
			ft_printf("sha512(%s)= ", ssl->name);
	}
	sha512_print_help(sha);
	(!(ssl->flag & SSL_R)) && ft_printf("\n");
	if (ssl->flag & SSL_R && !(ssl->flag & SSL_ST) && !(ssl->flag & SSL_P))
	{
		(!(ssl->flag & SSL_Q) && (ssl->flag & SSL_S)) &&
			ft_printf(" \"%s\"\n", ssl->name);
		(!(ssl->flag & SSL_Q) && !(ssl->flag & SSL_S)) &&
			ft_printf(" %s\n", ssl->name);
	}
}

static void		sha512_arg(t_sha512 *sha, int i)
{
	uint64_t	ch;
	uint64_t	maj;
	uint64_t	s0;
	uint64_t	s1;

	sha512_addstart(sha);
	while (++i < 80)
	{
		s1 = (u64_rr(sha->e, 14)) ^ (u64_rr(sha->e, 18)) ^ (u64_rr(sha->e, 41));
		ch = (sha->e & sha->f) ^ ((~sha->e) & sha->g);
		sha->t1 = sha->h + s1 + ch + g_sha512_k[i] + sha->w[i];
		s0 = (u64_rr(sha->a, 28)) ^ (u64_rr(sha->a, 34)) ^ (u64_rr(sha->a, 39));
		maj = (sha->a & sha->b) ^ (sha->a & sha->c) ^ (sha->b & sha->c);
		sha->t2 = s0 + maj;
		sha->h = sha->g;
		sha->g = sha->f;
		sha->f = sha->e;
		sha->e = sha->d + sha->t1;
		sha->d = sha->c;
		sha->c = sha->b;
		sha->b = sha->a;
		sha->a = sha->t1 + sha->t2;
	}
	sha512_addback(sha);
}

static void		sha512_transform(t_sha512 *sha)
{
	int			chunk;

	sha->h0 = 0x6a09e667f3bcc908;
	sha->h1 = 0xbb67ae8584caa73b;
	sha->h2 = 0x3c6ef372fe94f82b;
	sha->h3 = 0xa54ff53a5f1d36f1;
	sha->h4 = 0x510e527fade682d1;
	sha->h5 = 0x9b05688c2b3e6c1f;
	sha->h6 = 0x1f83d9abfb41bd6b;
	sha->h7 = 0x5be0cd19137e2179;
	chunk = 0;
	while (chunk < sha->set)
	{
		sha512_input(sha, chunk);
		sha512_arg(sha, -1);
		free(sha->w);
		chunk += 1;
	}
}

static void		sha512_padding(uint8_t *msg, size_t len, t_sha512 *sha)
{
	int			s;
	uint64_t	msg_len;

	msg_len = len * 8 + 1;
	while (msg_len % 1024 != 896)
		msg_len++;
	sha->set = (msg_len + 128) / 1024;
	if (!(sha->msg = malloc(sizeof(uint64_t) * 16 * sha->set)))
		return ;
	ft_bzero(sha->msg, sizeof(uint64_t) * 16 * sha->set);
	ft_memcpy((char *)sha->msg, msg, len);
	((char*)sha->msg)[len] = 0x80;
	s = 0;
	while (s < (sha->set * 16))
	{
		sha->msg[s] = swap_64bit((uint64_t)sha->msg[s]);
		s++;
	}
	sha->msg[(sha->set * 1024 - 128) / 64 + 1] = (uint64_t)len * 8;
}

int				ssl_sha512_init(uint8_t *msg, size_t len, t_ssl *ssl)
{
	t_sha512		sha;

	ft_bzero(&sha, sizeof(t_sha512));
	sha512_padding(msg, len, &sha);
	sha512_transform(&sha);
	sha512_print(&sha, ssl);
	ft_memdel((void **)&(sha.msg));
	return (0);
}
