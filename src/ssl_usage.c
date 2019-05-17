/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_dsusage.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/17 09:39:25 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/17 09:53:59 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void			display_usage(void)
{
	int		fd;
	char	buff[2];

	if ((fd = open("src/usage", O_RDONLY)) < 0)
		return ;
	while (read(fd, buff, 1) > 0)
	{
		buff[1] = '\0';
		write(1, &buff[0], 1);
	}
	close(fd);
}
