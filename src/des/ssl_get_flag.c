/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_get_flag.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/21 19:25:04 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/21 20:35:21 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static int		get_ssl_iv(t_ba64 *ba, char **av, int *i)
{


int				ssl_des_flag(t_ba64 *ba, int ac, char **av, int i)
{
	while (++i < ac)
	{
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
		else if (!(ft_strcmp(av[i], "-iv") && !get_ssl_iv(ba, av, &i)))
			return (0);
		else if (!(ft_strcmp(av[i], "-k") && !get_ssl_key(ba, av, &i)))
			return (0);
		else if (!(ft_strcmp(av[i], "-s") && !get_ssl_salt(ba, av, &i)))
			return (0);
		else
			return (ba64_error(av[i], W_UKNOW));
	}
	return (1);
}
