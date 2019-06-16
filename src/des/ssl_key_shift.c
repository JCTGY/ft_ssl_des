/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_key_shift.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/15 13:10:12 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/15 17:52:46 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

static void			des_half_key(uint64_t kh[16], uint64_t k0)
{
	int			i;
	uint64_t	add;
	uint64_t	temp;
	uint64_t	s;

	i = -1;
	s = k0;
	while (++i < 16)
	{
		add = s >> (28 - g_left_shift[i]);
		temp = s << g_left_shift[i];
		temp += add;
		temp = temp & 0xFFFFFFF;
		s = temp;
		kh[i] = temp;
	}
}

static uint64_t		des_pc1(uint64_t k)
{
	int			i;
	uint64_t	tmp;
	uint64_t	r;

	i = -1;
	r = 0;
	while (++i < 56)
	{
		tmp = (k >> (64 - g_des_pc1[i])) & 1;
		r <<= 1;
		r += tmp;
	}
	r <<= 8;
	return (r);
}

int					ssl_shift_key(t_ba64 *ba, t_key *k, uint64_t sk[16])
{
	uint64_t	temp;
	t_kindex	ki;

	ki.i = -1;
	temp = (*(uint64_t *)k->key);
	printf("key == %llx\n", (uint64_t)sk[ki.d]);
	temp = des_pc1(temp);
	des_half_key(ki.kc, (temp >> 36) & 0xFFFFFFF);
	des_half_key(ki.kd, (temp >> 8) & 0xFFFFFFF);
	while (++(ki.i) < 16)
	{
		ki.d = (ba->aoe == BA64_D) ? 15 - ki.i : ki.i;
		temp = (ki.kc[ki.i] << 28) + ki.kd[ki.i];
		ki.r = 0;
		ki.b = -1;
		while (++(ki.b) < 48)
		{
			ki.r <<= 1;
			ki.r += ((temp >> (56 - g_des_pc2[ki.b])) & 1);
		}
		sk[ki.d] = ki.r;
		printf("key == %llx\n", (uint64_t)sk[ki.d]);

	}
	return (0);
}
