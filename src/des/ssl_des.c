/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/21 19:01:21 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/14 21:55:20 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void			ssl_swap_data(t_ba64 *ba)
{
	ft_memdel((void *)&ba->msg);
	ba->msg = ft_memalloc(sizeof(uint8_t) * ba->len);
	ft_memcpy(ba->msg, ba->data, ba->len);
	ft_memdel((void *)&ba->data);
}

static void		ssl_des_decp(t_ba64 *ba, t_key *k)
{
	if (ba->a)
	{
		ssl_base64_algo(ba);
		ssl_swap_data(ba);
		ssl_des_algo(ba, k);
	}
	else if (!ba->a && ba->aoe == BA64_D)
		ssl_des_algo(ba, k);
}

static void		ssl_des_encp(t_ba64 *ba, t_key *k)
{
	if (!ba->a)
	{
		ssl_des_algo(ba, k);
		if (ba->aoe != BA64_D)
		{
			write(1, "Salted__", 8);
			write(1, k->salt, 8);
		}
	}
	else if (ba->a && ba->aoe != BA64_D)
	{
		ssl_des_algo(ba, k);
		ssl_swap_data(ba);
		ssl_base64_algo(ba);
	}
}

static void		ssl_des_aflag(t_ba64 *ba)
{
	t_key		k;

	ft_bzero(&k, sizeof(t_key));
	if (ba->aoe == BA64_D)
		ssl_des_decp(ba, &k);
	else if (ba->aoe != BA64_D)
		ssl_des_encp(ba, &k);
	write(1, ba->data, ba->len);
	ssl_free_k(&k);
}

int				ssl_base64_des(int ac, char **av)
{
	t_ba64		ba;

	ft_bzero(&ba, sizeof(ba));
	if (!ssl_des_flag(&ba, ac, av, 1))
		return (0);
	if (!ssl_base64_std(&ba))
		return (0);
	if (!ba.ofd)
		ssl_des_aflag(&ba);
	ssl_free_ba(&ba);
	return (1);
}
