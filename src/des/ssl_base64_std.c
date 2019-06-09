/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_base64_std.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/17 11:01:06 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/08 22:11:21 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static void		ssl_get_stdin(t_ba64 *ba)
{
	char	buff[2];
	char	*temp;
	int		ret;

	ba->msg = ft_strnew(1);
	while ((ret = (read(0, buff, 1))) > 0)
	{
		if (ret == 0)
			break ;
		buff[1] = '\0';
		temp = ba->msg;
		ba->msg = ft_strjoin(temp, buff);
		ft_strdel(&temp);
	}
}

static int		ssl_ba_check2(t_ba64 *ba)
{
	int			fd;
	mode_t		mode;

	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	if (ba->ofd == NULL)
		return (0);
	if ((fd = open(ba->ofd, O_WRONLY | O_CREAT | O_TRUNC, mode)) == -1)
	{
		if (errno == ENOENT)
			ft_printf("%s: No such file or directory\n", ba->ofd);
		else if (errno == EACCES)
			ft_printf("%s: Permission denied\n", ba->ofd);
		if (errno == EISDIR)
			ft_printf("%s is a directory\n", ba->ofd);
		return (-1);
	}
	if (!ft_strcmp(ba->cmd, "base64"))
		ssl_base64_algo(ba);
	else 
		ssl_des_output(ba);
	write(fd, ba->data, ba->len);
	close(fd);
	return (1);
}

static void		ssl_ba_stdin(t_ba64 *ba, int fd)
{
	char	buff[2];
	char	*temp;

	ba->msg = ft_strnew(1);
	while ((read(fd, buff, 1)) > 0)
	{
		buff[1] = '\0';
		temp = ba->msg;
		ba->msg = ft_strjoin(temp, buff);
		ft_strdel(&temp);
	}
}

static int		ssl_ba_check(t_ba64 *ba)
{
	int		fd;
	char	buff[2];

	if (ba->ifd == NULL)
		return (0);
	if ((fd = open(ba->ifd, O_RDONLY)) == -1)
	{
		if (errno == ENOENT)
			ft_printf("%s: No such file or directory\n", ba->ifd);
		else if (errno == EACCES)
			ft_printf("%s: Permission denied\n", ba->ifd);
		return (-1);
	}
	if ((read(fd, buff, 0)) == -1 && (errno == EISDIR))
	{
		ft_printf("%s is a directory\n", ba->ifd);
		return (-1);
	}
	ssl_ba_stdin(ba, fd);
	close(fd);
	return (1);
}

int				ssl_base64_std(t_ba64 *ba)
{
	if (ssl_ba_check(ba) == -1)
		return (0);
	if (ba->msg == NULL)
		ssl_get_stdin(ba);
	if (ssl_ba_check2(ba) == -1)
	{
		ssl_free_ba(ba);
		return (0);
	}
	return (1);
}
