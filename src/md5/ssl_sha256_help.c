/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha256_help.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/26 14:10:48 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/29 17:31:14 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_sha256.h"

void			sha256_addstart(t_sha256 *sha)
{
	sha->a = sha->h0;
	sha->b = sha->h1;
	sha->c = sha->h2;
	sha->d = sha->h3;
	sha->e = sha->h4;
	sha->f = sha->h5;
	sha->g = sha->h6;
	sha->h = sha->h7;
}

void			sha256_addback(t_sha256 *sha)
{
	sha->h0 += sha->a;
	sha->h1 += sha->b;
	sha->h2 += sha->c;
	sha->h3 += sha->d;
	sha->h4 += sha->e;
	sha->h5 += sha->f;
	sha->h6 += sha->g;
	sha->h7 += sha->h;
}

uint32_t		u32_rr(uint32_t w, uint32_t r)
{
	return (((w >> r) | (w << (32 - r))));
}

void			sha256_input(t_sha256 *sha, int chunk)
{
	int			i;
	uint32_t	s0;
	uint32_t	s1;

	sha->w = (uint32_t *)malloc(sizeof(uint32_t) * 64 * 8);
	ft_bzero(sha->w, sizeof(uint32_t) * 64 * 8);
	ft_memcpy(sha->w, &(sha->msg[16 * chunk]), 16 * 32);
	i = 16;
	while (i < 64)
	{
		s0 = (u32_rr(sha->w[i - 15], 7) ^\
				(u32_rr(sha->w[i - 15], 18)) ^ (sha->w[i - 15] >> 3));
		s1 = (u32_rr(sha->w[i - 2], 17) ^\
				(u32_rr(sha->w[i - 2], 19)) ^ (sha->w[i - 2] >> 10));
		sha->w[i] = sha->w[i - 16] + s0 + sha->w[i - 7] + s1;
		i++;
	}
}

uint32_t		swap_32bit(uint32_t r)
{
	return (((r >> 24) & 0xff) |
			((r << 8) & 0xff0000) |
			((r >> 8) & 0xff00) |
			((r << 24) & 0xff000000));
}
