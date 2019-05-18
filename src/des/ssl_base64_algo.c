/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_base64_algo.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/17 15:49:04 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/17 21:27:20 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_base64.h"

static void			ssl_base64_reline(t_ba64 *ba)
{
	int		nl;
	int		i;
	char	*re;

	nl = 0;
	i = -1;
	while (ba->msg[++i])
	{
		if (ba->msg[i] == '\n')
			nl++;
	}
	if (!nl)
		return ;
	re = ft_strnew(ft_strlen(ba->msg) - nl);
	i = 0;
	while (*ba->msg)
	{
		if (*ba->msg != '\n')
			re[i] = *ba->msg;
		(ba->msg)++;
	}
	ft_printf("is it herer\n");
//	ft_strdel(&(ba->msg));
	ba->msg = ft_strdup(re);
	ft_strdel(&re);
	printf("%s\n", ba->msg);
}

static int			check_base64(char *msg)
{
	int		i;

	i = -1;
	while (++i < (int)(ft_strlen(msg) - 1))
	{
		if (!ft_strchr(g_base64_encd, msg[i]) && msg[i] != '=')
			return (0);
	}
	return (1);
}

static int			ssl_base64_decode(t_ba64 *ba, t_balgo al)
{
	ssl_base64_reline(ba);
	if (!check_base64(ba->msg))
		return (dis_error(NULL, N_BASE64, 0, "data"));
	al.len = 0;
	return (1);
}

static void			ssl_base64_encode(t_ba64 *ba, t_balgo al)
{
	if (ba->msg == NULL)
		return ;
	al.old = ft_strlen(ba->msg);
	al.len = 4 * ((al.old + 2) / 3);
	al.len = al.len + (al.len / 64) + 1;
	ba->data = ft_strnew(al.len);
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
	al.m = al.old % 3 + 2;
	while (--al.m)
		ba->data[al.len - al.m] = '=';
	ba->data[al.len - 1] = '\n';
}

int				ssl_base64_algo(t_ba64 *ba)
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
