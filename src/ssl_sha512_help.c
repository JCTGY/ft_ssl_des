/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha512_help.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/29 18:38:05 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/29 19:25:24 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_sha512.h"

void			sha512_addstart(t_sha512 *sha)
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

void			sha512_addback(t_sha512 *sha)
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

uint64_t		u64_rr(uint64_t w, uint64_t r)
{
	return (((w >> r) | (w << (64 - r))));
}

void			sha512_input(t_sha512 *sha, int chunk)
{
	int			i;
	uint64_t	s0;
	uint64_t	s1;

	sha->w = (uint64_t *)malloc(sizeof(uint64_t) * 80 * 8);
	ft_bzero(sha->w, sizeof(uint64_t) * 80 * 8);
	ft_memcpy(sha->w, &(sha->msg[16 * chunk]), 16 * 80);
	i = 16;
	while (i < 80)
	{
		s0 = (u64_rr(sha->w[i - 15], 1) ^\
				(u64_rr(sha->w[i - 15], 8)) ^ (sha->w[i - 15] >> 7));
		s1 = (u64_rr(sha->w[i - 2], 19) ^\
				(u64_rr(sha->w[i - 2], 61)) ^ (sha->w[i - 2] >> 6));
		sha->w[i] = sha->w[i - 16] + s0 + sha->w[i - 7] + s1;
		i++;
	}
}

uint64_t		swap_64bit(uint64_t r)
{
	return (((r & 0xFF00000000000000) >> 56) |
			((r & 0x00FF000000000000) >> 40) |
			((r & 0x0000FF0000000000) >> 24) |
			((r & 0x000000FF00000000) >> 8) |
			((r & 0x00000000FF000000) << 8) |
			((r & 0x0000000000FF0000) << 24) |
			((r & 0x000000000000FF00) << 40) |
			((r & 0x00000000000000FF) << 56));
}
