/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_calculate.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/18 19:04:55 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/29 19:51:06 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

t_hash		g_hash[6] =
{
	{ "md5", &ssl_md5_init },
	{ "sha256", &ssl_sha256_init },
	{ "sha224", &ssl_sha224_init },
	{ "sha384", &ssl_sha384_init },
	{ "sha512", &ssl_sha512_init },
	{ NULL, NULL },
};

int			hash_calculate(t_ssl *ssl, char *hash)
{
	int		i;

	i = -1;
	while (g_hash[++i].hash)
	{
		if (!ft_strcmp(hash, g_hash[i].hash))
			return (g_hash[i].func((uint8_t *)ssl->msg,\
						ft_strlen(ssl->msg), ssl));
	}
	return (0);
}
