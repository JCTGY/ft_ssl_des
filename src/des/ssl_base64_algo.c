/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_base64_algo.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/17 15:49:04 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/21 19:10:27 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_base64.h"
#include "ft_ssl.h"

static void			ssl_base64_dchelp(t_ba64 *ba, t_balgo al)
{
	while (al.x < al.old)
	{
		al.ta = (ba->msg[al.x] == '=') ?
			0 & al.x++ : g_base64_decd[(int)ba->msg[al.x++]];
		al.tb = (ba->msg[al.x] == '=') ?
			0 & al.x++ : g_base64_decd[(int)ba->msg[al.x++]];
		al.tc = (ba->msg[al.x] == '=') ?
			0 & al.x++ : g_base64_decd[(int)ba->msg[al.x++]];
		al.td = (ba->msg[al.x] == '=') ?
			0 & al.x++ : g_base64_decd[(int)ba->msg[al.x++]];
		al.al = (al.ta << 18) + (al.tb << 12) + (al.tc << 6) + (al.td);
		ba->data[al.y++] = ((al.al >> 2 * 8) & 127);
		ba->data[al.y++] = ((al.al >> 1 * 8) & 127);
		ba->data[al.y++] = ((al.al >> 0 * 8) & 127);
	}
}

static int			ssl_base64_decode(t_ba64 *ba, t_balgo al)
{
	if (!ssl_base64_reline(ba, ft_strlen(ba->msg)) ||
			(!check_base64(ba->msg)) || (ft_strlen(ba->msg) % 4))
		return (dis_error(NULL, N_BASE64, 0, "data"));
	al.old = ft_strlen(ba->msg);
	al.len = 3 * (al.old / 4);
	ba->data = ft_strnew(al.len);
	ssl_base64_dchelp(ba, al);
	ba->data[al.len] = '\0';
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
	al.old = ft_strlen(ba->msg);
	al.len = 4 * ((al.old + 2) / 3);
	al.len = al.len + (al.len / 64) + 1;
	ba->data = ft_strnew(al.len);
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
	if (!ba->ofd)
		ft_printf("%s", ba->data);
	return (0);
}
