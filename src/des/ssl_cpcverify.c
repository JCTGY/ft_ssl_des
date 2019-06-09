/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_cpverift.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/16 09:59:41 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/24 19:37:21 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int		ssl_cpcverify(int ac, char **av)
{
	if (!(ft_strcmp(av[1], "base64")))
		ssl_base64(ac, av);
	else if (!(ft_strcmp(av[1], "des")) || !(ft_strcmp(av[1], "des-ecb")))
		ssl_base64_des(ac, av);
	return (0);
}
