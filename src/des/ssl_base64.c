/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_base64.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/17 13:06:30 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/22 20:35:51 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void			ssl_free_ba(t_ba64 *ba)
{
	if (!ba)
		return ;
	if (ba->skey)
		ft_strdel(&ba->skey);
	if (ba->msg)
		ft_strdel(&ba->msg);
	if (ba->data)
		ft_strdel(&ba->data);
}

static int		ssl_base64_flag(t_ba64 *ba, int ac, char **av, int i)
{
	while (++i < ac)
	{
		ba->cmd = av[1];
		if (!(ft_strcmp(av[i], "-i")) && (i + 1 >= ac))
			return (ba64_error(av[i], W_NOFILE));
		else if (!ft_strcmp(av[i], "-i"))
			ba->ifd = av[++i];
		else if (!(ft_strcmp(av[i], "-o")) && (i + 1 >= ac))
			return (ba64_error(av[i], W_NOFILE));
		else if (!ft_strcmp(av[i], "-o"))
			ba->ofd = av[++i];
		else if (!(ft_strcmp(av[i], "-d")))
			ba->aoe = BA64_D;
		else if (!(ft_strcmp(av[i], "-e")))
			ba->aoe = BA64_E;
		else
			return (ba64_error(av[i], W_UKNOW));
	}
	return (1);
}

int				ssl_base64(int ac, char **av)
{
	t_ba64		ba;

	ft_bzero(&ba, sizeof(ba));
	if (!ssl_base64_flag(&ba, ac, av, 1))
		return (0);
	if (!ssl_base64_std(&ba))
		return (0);
	if (!ba.ofd)
		ssl_base64_algo(&ba);
	ssl_free_ba(&ba);
	return (1);
}
