/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_help.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/05 12:53:40 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/15 11:07:30 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"
#include "ft_sha512.h"

void			ssl_free_k(t_key *k)
{
	ft_memdel((void *)&k->msg);
	ft_memdel((void *)&k->key);
	ft_memdel((void *)&k->salt);
	ft_memdel((void *)&k->iv);
}

static uint8_t	change_hex_help(char s1)
{
	if (s1 >= 'a' && s1 <= 'f')
		return (s1 - 'a' + 10);
	else if (s1 >= 'A' && s1 <= 'F')
		return (s1 - 'A' + 10);
	else if (s1 >= '0' && s1 <= '9')
		return (s1 - '0');
	else if (s1 == '\0')
		return (0);
	return (-1);
}

static int		change_hex(char s1, char s2, t_key *k, t_vai *v)
{
	uint8_t		temp;

	if (!(temp = change_hex_help(s1)))
		return (0);
	temp <<= 4;
	temp += change_hex_help(s2);
	if (v->va == I_SALT)
		k->salt[v->i] = temp;
	else if (v->va == I_KEY)
		k->key[v->i] = temp;
	else if (v->va == I_IV)
		k->iv[v->i] = temp;
	if (!change_hex_help(s2))
	{
		v->i--;
		return (0);
	}
	return (1);
}

int				ssl_hex_to_by(uint8_t *hex, t_key *k, int va)
{
	t_vai		v;

	v.i = 7;
	v.va = va;
	while (v.i >= 0)
	{
		if (!change_hex(hex[(7 - v.i) * 2], hex[(7 - v.i) * 2 + 1], k, &v))
			break ;
		v.i--;
	}
	while (v.i >= 0)
	{
		if (va == I_SALT)
			k->salt[v.i--] = 0;
		else if (va == I_KEY)
			k->key[v.i--] = 0;
		else if (va == I_IV)
			k->iv[v.i--] = 0;
	}
	if (va == I_SALT)
		*(uint64_t*)k->salt = swap_64bit(*(uint64_t*)k->salt);
	printf("key == %llx\n", *(uint64_t*)k->key);
	printf("iv == %llx\n", *(uint64_t*)k->iv);
	return (0);
}

int				decode_salt(t_ba64 *ba, t_key *k)
{
	if (!ft_strncmp((char *)ba->msg, "Salted__", 8))
	{
		ft_memcpy(k->salt, ba->msg + 8, 8);
		k->msg = ft_strdup(&(*((char *)ba->msg + 16)));
		return (0);
	}
	return (1);
}
