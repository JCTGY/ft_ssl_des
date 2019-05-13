/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha_print.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/29 17:13:47 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/29 19:50:36 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_sha256.h"
#include "ft_sha512.h"

void		sha256_print_help(t_sha256 *sha)
{
	ft_printf("%08x%08x%08x%08x", sha->h0, sha->h1, sha->h2, sha->h3);
	ft_printf("%08x%08x%08x%08x", sha->h4, sha->h5, sha->h6, sha->h7);
}

void		sha224_print_help(t_sha256 *sha)
{
	ft_printf("%08x%08x%08x%08x", sha->h0, sha->h1, sha->h2, sha->h3);
	ft_printf("%08x%08x%08x", sha->h4, sha->h5, sha->h6);
}

void		sha512_print_help(t_sha512 *sha)
{
	ft_printf("%016llx%016llx%016llx%016llx",\
			sha->h0, sha->h1, sha->h2, sha->h3);
	ft_printf("%016llx%016llx%016llx%016llx",\
			sha->h4, sha->h5, sha->h6, sha->h7);
}

void		sha384_print_help(t_sha512 *sha)
{
	ft_printf("%016llx%016llx%016llx%016llx",\
			sha->h0, sha->h1, sha->h2, sha->h3);
	ft_printf("%016llx%016llx",\
			sha->h4, sha->h5);
}
