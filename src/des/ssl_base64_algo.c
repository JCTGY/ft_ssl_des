/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_base64_algo.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/17 15:49:04 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/15 13:05:40 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_base64.h"
#include "ft_ssl.h"

static int			ssl_base64_dchelp(t_ba64 *ba, t_balgo al)
{
	while (al.x < al.old)
	{
		ba->data[al.y] = ssl_base64_deta(ba->msg[al.x++]) << 2;
		al.tmp = ssl_base64_deta(ba->msg[al.x++]);
		ba->data[al.y++] += (al.tmp >> 4) & 3;
		ba->data[al.y] = (al.tmp & 15) << 4;
		al.tmp = ssl_base64_deta(ba->msg[al.x++]);
		ba->data[al.y++] += (al.tmp >> 2) & 15;
		ba->data[al.y] = (al.tmp & 3) << 6;
		ba->data[al.y++] += ssl_base64_deta(ba->msg[al.x++]) & 63;
	}
	if ((ba->msg[al.x - 1] == '=') && (ba->msg[al.x - 2] == '='))
		ba->data[--al.y] = 0;
	if (ba->msg[al.x - 1] == '=')
		ba->data[--al.y] = 0;
	return (al.y);
}

static int			ssl_base64_decode(t_ba64 *ba, t_balgo al)
{
	if (!ssl_base64_reline(ba, ft_strlen((char*)ba->msg)) ||
			(!check_base64((char*)ba->msg)) || (ft_strlen((char*)ba->msg) % 4))
		return (dis_error(NULL, N_BASE64, 0, "data"));
	al.old = (!ba->len) ? ft_strlen((char *)ba->msg) : ba->len;
	al.len = 3 * (al.old / 4);
	ba->data = ft_memalloc(sizeof(uint8_t) * al.len + 1);
	ba->len = ssl_base64_dchelp(ba, al);
	ba->data[ba->len] = '\0';
	return (1);
}

static void			ssl_base64_enhelp(t_ba64 *ba, t_balgo al)
{
	while (al.x < al.old)
	{
		al.ta = al.x < al.old ? (uint8_t)ba->msg[al.x++] : 0;
		al.tb = al.x < al.old ? (uint8_t)ba->msg[al.x++] : 0;
		al.tc = al.x < al.old ? (uint8_t)ba->msg[al.x++] : 0;
		al.al = (al.ta << 16) + (al.tb << 8) + (al.tc);
		ba->data[al.y++] = g_base64_encd[(al.al >> 3 * 6) & 63];
		ba->data[al.y++] = g_base64_encd[(al.al >> 2 * 6) & 63];
		ba->data[al.y++] = g_base64_encd[(al.al >> 1 * 6) & 63];
		ba->data[al.y++] = g_base64_encd[(al.al >> 0 * 6) & 63];
		if (((al.y - al.c) % 64 == 0) && (al.y >= 64))
		{
			ba->data[al.y++] = '\n';
			al.c++;
		}
	}
}

static void			ssl_base64_encode(t_ba64 *ba, t_balgo al)
{
	if (ba->msg == NULL)
		return ;
	al.old = (!ft_strcmp(ba->cmd, "base64"))
		? ft_strlen((char *)ba->msg) : ba->len;
	al.len = 4 * ((al.old + 2) / 3);
	al.len = al.len + (al.len / 64) + 1;
	ba->len = al.len;
	ba->data = ft_memalloc(sizeof(uint8_t) * al.len + 1);
	ssl_base64_enhelp(ba, al);
	al.m = (al.old % 3) ? (5 - al.old % 3) : 1;
	while (--al.m)
		ba->data[al.len - al.m] = '=';
	ba->data[al.len - 1] = '\n';
}

int					ssl_base64_algo(t_ba64 *ba)
{
	t_balgo		al;

	ft_bzero(&al, sizeof(al));
	if (ba->aoe == BA64_E || !ba->aoe)
		ssl_base64_encode(ba, al);
	if (ba->aoe == BA64_D)
		ssl_base64_decode(ba, al);
	if (!ba->ofd && !ft_strcmp(ba->cmd, "base64"))
		write(1, ba->data, ba->len);
	return (0);
}
