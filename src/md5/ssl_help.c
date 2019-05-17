/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_help.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/16 18:56:35 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/16 09:31:58 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void			del_str(t_ssl *ssl)
{
	ft_strdel(&ssl->msg);
	ft_strdel(&ssl->name);
}

int				mini_gnl(t_ssl *ssl, char *hash)
{
	int		ret;
	char	*temp;
	char	*str;
	char	buff[2];

	(!(ssl->flag & SSL_P)) && (ssl->flag |= SSL_ST);
	str = ft_strnew(1);
	ret = 0;
	buff[1] = '\0';
	while ((ret = read(0, buff, 1)) > 0)
	{
		if (ret == 0)
			break ;
		temp = str;
		str = ft_strjoin(temp, buff);
		free(temp);
	}
	ssl->name = str;
	ssl->msg = ft_strdup(ssl->name);
	hash_calculate(ssl, hash);
	del_str(ssl);
	return (1);
}

int				initiate_p(t_ssl *ssl, char *hash)
{
	ssl->flag |= SSL_P;
	ssl->p_flg += 1;
	if (ssl->p_flg == 1)
		mini_gnl(ssl, hash);
	else
	{
		ssl->flag |= SSL_PP;
		ssl->msg = ft_strnew(0);
		hash_calculate(ssl, hash);
	}
	del_str(ssl);
	ssl->flag ^= SSL_P;
	return (1);
}
