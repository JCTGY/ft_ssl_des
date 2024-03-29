/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_base64_help.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/20 18:18:11 by jchiang-          #+#    #+#             */
/*   Updated: 2019/07/03 08:52:37 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_base64.h"

int				check_base64(char *msg)
{
	int		i;

	i = -1;
	while (++i < (int)(ft_strlen(msg) - 1))
	{
		if (!ft_strchr(g_base64_encd, msg[i]) &&
				(i < ((int)ft_strlen(msg) - 2)) && msg[i] != '=')
			return (0);
	}
	return (1);
}

uint8_t			ssl_base64_deta(uint8_t c)
{
	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	else if (c >= 'a' && c <= 'z')
		return (c - 'a' + 26);
	else if (c >= '0' && c <= '9')
		return (c - '0' + 52);
	else if (c == '+')
		return (62);
	else if (c == '/')
		return (63);
	else if (c == '=')
		return (0);
	return (-1);
}

static void		ssl_reline_help(t_ba64 *ba, t_index in, char *temp)
{
	if (ba->msg[in.i - 1] == '\0')
		temp[in.t - 1] = '\0';
	else
		temp[in.t] = '\0';
	ft_memdel((void *)&ba->msg);
	ba->msg = ft_memalloc(sizeof(uint8_t) * in.i);
	ft_memcpy(ba->msg, temp, in.i);
	ft_memdel((void*)&temp);
}

int				ssl_base64_reline(t_ba64 *ba, int len)
{
	char		*temp;
	t_index		in;

	ft_bzero(&in, sizeof(in));
	in.i = -1;
	in.c = len / 64;
	temp = ft_strnew(ft_strlen((char*)ba->msg));
	while (ba->msg[++in.i])
	{
		if (((in.i - in.n) % 64 == 0) && (in.i >= 64))
		{
			if (ba->msg[in.i] != '\n')
				return (0);
		}
		else if (ba->msg[in.i] != '\n')
			temp[in.t++] = ba->msg[in.i];
		if (ba->msg[in.i - 1] == '\n')
			in.n++;
	}
	if (ba->msg[in.i - 1] != '\n' && in.c != in.n)
		return (0);
	ssl_reline_help(ba, in, temp);
	return (1);
}
