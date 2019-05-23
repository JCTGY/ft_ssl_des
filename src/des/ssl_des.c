/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/21 19:01:21 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/22 20:12:28 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int				ssl_base64_des(int ac, char **av)
{
	t_ba64		ba;

	ft_bzero(&ba, sizeof(ba));
	if (!ssl_des_flag(&ba, ac, av, 1))
		return (0);
	if (!ssl_base64_std(&ba))
		return (0);
	if (!ba.ofd && ba.a == BA64_A)
		ssl_base64_algo(&ba);
	ssl_free_ba(&ba);
	return (1);
}
