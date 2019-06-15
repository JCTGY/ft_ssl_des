/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_output.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/08 20:14:01 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/14 21:25:35 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

static void		ssl_re_output(t_ba64 *ba, int fd)
{
	close(fd);
	ba->a = 0;
	ba->len += 16;
	ba->ifd = ba->ofd;
	ba->cmd = ft_strdup("2nd64");
	ssl_base64_std(ba);
}

int			ssl_des_output(t_ba64 *ba, int fd)
{
	t_key		k;

	ft_bzero(&k, sizeof(k));
	if (ba->aoe == BA64_D && ba->a)
	{
		ssl_base64_algo(ba);
		ssl_swap_data(ba);
	}
	ssl_des_algo(ba, &k);
	if (ba->aoe != BA64_D)
	{
		write(fd, "Salted__", 8);
		write(fd, k.salt, 8);
	}	
	write(fd, ba->data, ba->len);
	if (ba->aoe != BA64_D && ft_strcmp(ba->cmd, "base64") && ba->a)
		ssl_re_output(ba, fd);
	ssl_free_k(&k);
	return (0);
}
