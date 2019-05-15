/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_md5_help.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/25 07:46:12 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/26 21:02:46 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_md5.h"

uint32_t		md5_left_rotate(uint32_t f, uint32_t s)
{
	return ((f << s) | (f >> (32 - s)));
}

void			md5_addback(t_md5 *md5)
{
	md5->a0 = md5->a + md5->a0;
	md5->b0 = md5->b + md5->b0;
	md5->c0 = md5->c + md5->c0;
	md5->d0 = md5->d + md5->d0;
}

void			md5_addstart(t_md5 *md5)
{
	md5->a = md5->a0;
	md5->b = md5->b0;
	md5->c = md5->c0;
	md5->d = md5->d0;
}

uint32_t		md5_swap_bit(uint32_t swap)
{
	uint32_t	r;

	r = ((swap >> 24) |
			((swap >> 8) & 0xff00) |
			((swap << 8) & 0xff0000) |
			(swap << 24));
	return (r);
}

void			md5_endianfix(t_md5 *md5)
{
	md5->a0 = md5_swap_bit(md5->a0);
	md5->b0 = md5_swap_bit(md5->b0);
	md5->c0 = md5_swap_bit(md5->c0);
	md5->d0 = md5_swap_bit(md5->d0);
}
