/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha224.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/29 18:05:13 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/29 18:19:53 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_sha256.h"

static void		sha224_print(t_sha256 *sha, t_ssl *ssl)
{
	if (ssl->flag & SSL_P)
	{
		(!(ssl->flag & SSL_PP)) && ft_printf("%s", ssl->name);
		sha224_print_help(sha);
		return ;
	}
	if (!(ssl->flag & SSL_R) && !(ssl->flag & SSL_ST) && !(ssl->flag & SSL_P))
	{
		(!(ssl->flag & SSL_Q) && (ssl->flag & SSL_S)) &&
			ft_printf("sha224(\"%s\")= ", ssl->name);
		(!(ssl->flag & SSL_Q) && !(ssl->flag & SSL_S)) &&
			ft_printf("sha224(%s)= ", ssl->name);
	}
	sha224_print_help(sha);
	(!(ssl->flag & SSL_R)) && ft_printf("\n");
	if (ssl->flag & SSL_R && !(ssl->flag & SSL_ST) && !(ssl->flag & SSL_P))
	{
		(!(ssl->flag & SSL_Q) && (ssl->flag & SSL_S)) &&
			ft_printf(" \"%s\"\n", ssl->name);
		(!(ssl->flag & SSL_Q) && !(ssl->flag & SSL_S)) &&
			ft_printf(" %s\n", ssl->name);
	}
}

static void		sha224_arg(t_sha256 *sha, int i)
{
	uint32_t	ch;
	uint32_t	maj;
	uint32_t	s0;
	uint32_t	s1;

	sha256_addstart(sha);
	while (++i < 64)
	{
		s1 = (u32_rr(sha->e, 6)) ^ (u32_rr(sha->e, 11)) ^ (u32_rr(sha->e, 25));
		ch = (sha->e & sha->f) ^ ((~sha->e) & sha->g);
		sha->t1 = sha->h + s1 + ch + g_sha256_k[i] + sha->w[i];
		s0 = (u32_rr(sha->a, 2)) ^ (u32_rr(sha->a, 13)) ^ (u32_rr(sha->a, 22));
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
	sha256_addback(sha);
}

static void		sha224_transform(t_sha256 *sha)
{
	int			chunk;

	sha->h0 = 0xc1059ed8;
	sha->h1 = 0x367cd507;
	sha->h2 = 0x3070dd17;
	sha->h3 = 0xf70e5939;
	sha->h4 = 0xffc00b31;
	sha->h5 = 0x68581511;
	sha->h6 = 0x64f98fa7;
	sha->h7 = 0xbefa4fa4;
	chunk = 0;
	while (chunk < sha->set)
	{
		sha256_input(sha, chunk);
		sha224_arg(sha, -1);
		free(sha->w);
		chunk += 1;
	}
}

static void		sha224_padding(uint8_t *msg, size_t len, t_sha256 *sha)
{
	int			s;
	uint32_t	msg_len;

	msg_len = len * 8 + 1;
	while (msg_len % 512 != 448)
		msg_len++;
	sha->set = (msg_len + 64) / 512;
	if (!(sha->msg = malloc(sizeof(uint32_t) * 16 * sha->set)))
		return ;
	ft_bzero(sha->msg, sizeof(uint32_t) * 16 * sha->set);
	ft_memcpy((char *)sha->msg, msg, len);
	((char*)sha->msg)[len] = 0x80;
	s = 0;
	while (s < (sha->set * 16))
	{
		sha->msg[s] = swap_32bit((uint32_t)sha->msg[s]);
		s++;
	}
	sha->msg[(msg_len) / 32 + 1] = (uint32_t)len * 8;
}

int				ssl_sha224_init(uint8_t *msg, size_t len, t_ssl *ssl)
{
	t_sha256		sha;

	ft_bzero(&sha, sizeof(t_sha256));
	sha224_padding(msg, len, &sha);
	sha224_transform(&sha);
	sha224_print(&sha, ssl);
	ft_memdel((void **)&(sha.msg));
	return (0);
}
