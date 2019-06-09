/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_md5.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/18 19:26:21 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/05 20:02:23 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_md5.h"

static void		md5_print(t_ssl *ssl, t_md5 *md5)
{
	md5_endianfix(md5);
	if (ssl->flag & SSL_P)
	{
		(!(ssl->flag & SSL_PP)) && ft_printf("%s", ssl->name);
		ft_printf("%08x%08x%08x%08x\n", md5->a0, md5->b0, md5->c0, md5->d0);
		return ;
	}
	if (!(ssl->flag & SSL_R) && !(ssl->flag & SSL_ST) && !(ssl->flag & SSL_P))
	{
		(!(ssl->flag & SSL_Q) && (ssl->flag & SSL_S)) &&
			ft_printf("MD5 (\"%s\") = ", ssl->name);
		(!(ssl->flag & SSL_Q) && !(ssl->flag & SSL_S)) &&
			ft_printf("MD5 (%s) = ", ssl->name);
	}
	ft_printf("%08x%08x%08x%08x", md5->a0, md5->b0, md5->c0, md5->d0);
	(!(ssl->flag & SSL_R)) && ft_printf("\n");
	if (ssl->flag & SSL_R && !(ssl->flag & SSL_ST) && !(ssl->flag & SSL_P))
	{
		(!(ssl->flag & SSL_Q) && (ssl->flag & SSL_S)) &&
			ft_printf(" \"%s\"\n", ssl->name);
		(!(ssl->flag & SSL_Q) && !(ssl->flag & SSL_S)) &&
			ft_printf(" %s\n", ssl->name);
	}
}

static void		md5_arg(uint32_t *msg, t_md5 *md5)
{
	uint32_t	i;
	uint32_t	f;
	uint32_t	temp;

	i = 0;
	md5_addstart(md5);
	while (i < 64)
	{
		if (i < 16)
			f = (md5->b & md5->c) | ((~md5->b) & md5->d);
		else if (i > 15 && i < 32)
			f = (md5->d & md5->b) | ((~md5->d) & md5->c);
		else if (i > 31 && i < 48)
			f = md5->b ^ md5->c ^ md5->d;
		else if (i > 47 && i < 64)
			f = md5->c ^ (md5->b | (~md5->d));
		temp = md5->d;
		md5->d = md5->c;
		md5->c = md5->b;
		md5->b = md5->b + md5_left_rotate(f + md5->a +\
				g_md5_k[i] + msg[g_md5_m[i]], g_md5_s[i]);
		md5->a = temp;
		i++;
	}
	md5_addback(md5);
}

static void		md5_transform(t_md5 *md5)
{
	uint32_t	chunk;

	chunk = 0;
	while (chunk < md5->msg_len)
	{
		md5_arg((uint32_t *)(md5->msg + chunk), md5);
		chunk = chunk + 64;
	}
}

static void		md5_padding(uint8_t *msg, size_t len, t_md5 *md5)
{
	size_t		i;

	md5->a0 = 0x67452301;
	md5->b0 = 0xefcdab89;
	md5->c0 = 0x98badcfe;
	md5->d0 = 0x10325476;
	md5->msg_len = len * 8 + 1;
	while (md5->msg_len % 512 != 448)
		md5->msg_len++;
	if (!(md5->msg = ft_memalloc(md5->msg_len + 64)))
		return ;
	ft_strcpy((char *)md5->msg, (const char *)msg);
	md5->msg_len /= 8;
	i = len;
	md5->msg[i] = 128;
	while (++i < md5->msg_len)
		md5->msg[i] = 0;
	*(uint32_t*)(md5->msg + i) = (uint32_t)len * 8;
}

int				ssl_md5_init(uint8_t *msg, size_t len, t_ssl *ssl)
{
	t_md5		md5;

	ft_bzero(&md5, sizeof(t_md5));
	md5_padding(msg, len, &md5);
	md5_transform(&md5);
	if (ssl->p_flg & SSL_DES)
	{
		ft_memdel((void **)&(md5.msg));
		md5_endianfix(&md5);
		ssl->md5[0] = md5.a0;
		ssl->md5[0] <<= 32;
		ssl->md5[0] += md5.b0;
		ssl->md5[1] = md5.c0;
		ssl->md5[1] <<= 32;
		ssl->md5[1] += md5.d0;
		return (1);
	}
	md5_print(ssl, &md5);
	ft_memdel((void **)&(md5.msg));
	return (0);
}
