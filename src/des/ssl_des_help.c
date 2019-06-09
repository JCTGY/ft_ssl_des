/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_help.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/05 12:53:40 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/06 10:57:55 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

static int		change_hex(char s1, char s2, t_key *k, t_vai v)
{
	uint8_t		temp;

	temp = 0;
	if (s1 >= 'a' && s1 <= 'f')
		temp = s1 - 'a' + 10;
	else if (s1 >= 'A' && s1 <= 'F')
		temp = s1 - 'A' + 10;
	else if (s1 >= '0' && s1 <= '9')
		temp = s1 - '0';
	else if (s1 == '\0' || s2 == '\0')
		return (0);
	temp <<= 4;
	if (s2 >= 'a' && s2 <= 'f')
		temp += s2 - 'a' + 10;
	else if (s2 >= 'A' && s2 <= 'F')
		temp += s2 - 'A' + 10;
	else if (s2 >= '0' && s2 <= '9')
		temp += s2 - '0';
	if (v.va == I_SALT)
		k->salt[v.i] = temp;
	else if (v.va == I_KEY)
		k->key[v.i] = temp;
	else if (v.va == I_IV)
		k->iv[v.i] = temp;
	return (1);
}

int				ssl_hex_to_by(char *hex, t_key *k, int va)
{
	t_vai		v;

	v.i = -1;
	v.va = va;
	while (++v.i < 8)
	{
		if (!change_hex(hex[v.i * 2], hex[v.i * 2 + 1], k, v))
			break ;
	}
	while (v.i < 8)
	{
		if (va == I_SALT)
			k->salt[v.i++] = 0;
		else if (va == I_KEY)
			k->key[v.i++] = 0;
		else if (va == I_IV)
			k->iv[v.i++] = 0;
	}
	return (0);
}

int				decode_salt(t_ba64 *ba, t_key *k)
{
	if (!ft_strncmp(ba->msg, "Salted__", 8))
	{
	//	k->salt = (char *)malloc(sizeof(char) * 8 + 1);
		ft_memcpy(k->salt, ba->msg + 8, 8);
		k->msg = ft_strdup(&(*(ba->msg + 16)));
		return (0);
	}
	return (1);
}
