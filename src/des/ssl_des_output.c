/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_output.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/08 20:14:01 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/11 09:04:37 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_des.h"

int			ssl_des_output(t_ba64 *ba)
{
	ssl_des_algo(ba);
	if (ba->a)
	{
		ft_strdel(&ba->msg);
		ba->msg = (char *)ft_memalloc(sizeof(char) * ba->len + 1);
		if (ba->salt && ba->aoe != BA64_D)
			ft_memcpy(ba->msg + 16, ba->data, sizeof(char) * ba->len);
		else
			ft_memcpy(ba->msg, ba->data, sizeof(char) * ba->len);
		ft_strdel(&(ba->data));
		ssl_base64_algo(ba);
	}
	return (0);
}
