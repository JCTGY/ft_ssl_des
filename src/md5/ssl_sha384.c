/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha384.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/29 19:46:13 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/29 19:52:45 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_sha512.h"

static void		sha384_print(t_sha512 *sha, t_ssl *ssl)
{
	if (ssl->flag & SSL_P)
	{
		(!(ssl->flag & SSL_PP)) && ft_printf("%s", ssl->name);
		sha384_print_help(sha);
		return ;
	}
	if (!(ssl->flag & SSL_R) && !(ssl->flag & SSL_ST) && !(ssl->flag & SSL_P))
	{
		(!(ssl->flag & SSL_Q) && (ssl->flag & SSL_S)) &&
			ft_printf("sha384(\"%s\")= ", ssl->name);
		(!(ssl->flag & SSL_Q) && !(ssl->flag & SSL_S)) &&
			ft_printf("sha384(%s)= ", ssl->name);
	}
	sha384_print_help(sha);
	(!(ssl->flag & SSL_R)) && ft_printf("\n");
	if (ssl->flag & SSL_R && !(ssl->flag & SSL_ST) && !(ssl->flag & SSL_P))
	{
		(!(ssl->flag & SSL_Q) && (ssl->flag & SSL_S)) &&
			ft_printf(" \"%s\"\n", ssl->name);
		(!(ssl->flag & SSL_Q) && !(ssl->flag & SSL_S)) &&
			ft_printf(" %s\n", ssl->name);
	}
}

static void		sha384_arg(t_sha512 *sha, int i)
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

static void		sha384_transform(t_sha512 *sha)
{
	int			chunk;

	sha->h0 = 0xcbbb9d5dc1059ed8;
	sha->h1 = 0x629a292a367cd507;
	sha->h2 = 0x9159015a3070dd17;
	sha->h3 = 0x152fecd8f70e5939;
	sha->h4 = 0x67332667ffc00b31;
	sha->h5 = 0x8eb44a8768581511;
	sha->h6 = 0xdb0c2e0d64f98fa7;
	sha->h7 = 0x47b5481dbefa4fa4;
	chunk = 0;
	while (chunk < sha->set)
	{
		sha512_input(sha, chunk);
		sha384_arg(sha, -1);
		free(sha->w);
		chunk += 1;
	}
}

static void		sha384_padding(uint8_t *msg, size_t len, t_sha512 *sha)
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

int				ssl_sha384_init(uint8_t *msg, size_t len, t_ssl *ssl)
{
	t_sha512		sha;

	ft_bzero(&sha, sizeof(t_sha512));
	sha384_padding(msg, len, &sha);
	sha384_transform(&sha);
	sha384_print(&sha, ssl);
	ft_memdel((void **)&(sha.msg));
	return (0);
}
