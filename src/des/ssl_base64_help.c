/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_base64_help.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/20 18:18:11 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/21 13:42:32 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_base64.h"

int			check_base64(char *msg)
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

int			ssl_base64_reline(t_ba64 *ba, int len)
{
	char		*temp;
	t_index		in;

	ft_bzero(&in, sizeof(in));
	in.i = -1;
	in.c = len / 64;
	temp = ft_strnew(ft_strlen(ba->msg));
	while (ba->msg[++in.i])
	{
		if (((in.i - in.n) % 64 == 0) && (in.i >= 64))
		{
			if (ba->msg[in.i] != '\n')
				return (0);
		}
		else
			temp[in.t++] = ba->msg[in.i];
		if (ba->msg[in.i - 1] == '\n')
			in.n++;
	}
	if (ba->msg[in.i - 1] != '\n' || in.c != in.n)
		return (0);
	temp[in.t - 1] = '\0';
	ft_strdel(&ba->msg);
	ba->msg = ft_strdup(temp);
	return (1);
}
