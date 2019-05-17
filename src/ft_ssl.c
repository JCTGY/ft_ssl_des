/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/16 18:08:12 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/17 10:59:54 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static int		ssl_stdin(t_ssl *ssl)
{
	char		hash[10];
	int			ret;

	ft_printf("ft_SSL> ");
	ret = read(0, &hash, 10);
	hash[ret - 1] = '\0';
	if (!(check_error(hash)))
		return (ssl_stdin(ssl));
	mini_gnl(ssl, hash);
	ssl->name = 0;
	return (0);
}

static int		allocate_sflag(char **argv, t_ssl *ssl, int i, int x)
{
	ssl->flag |= SSL_S;
	if (argv[i][x + 1] != '\0')
	{
		ssl->name = ft_strnew(ft_strlen(argv[i]) - x);
		ft_strcpy(ssl->name, argv[i] + x + 1);
		ssl->msg = ft_strdup(ssl->name);
	}
	else if (ssl->flag & SSL_S && !argv[i + 1])
		return (dis_error(argv[1], S_NO_ARG, 's', argv[i + 1]));
	else if (argv[i + 1])
	{
		i++;
		ssl->name = ft_strnew(ft_strlen(argv[i]));
		ft_strcpy(ssl->name, argv[i]);
		ssl->msg = ft_strdup(ssl->name);
	}
	hash_calculate(ssl, argv[1]);
	del_str(ssl);
	return (i);
}

static int		collect_flags(char **argv, t_ssl *ssl)
{
	int		i;
	int		x;

	i = 1;
	while (argv[++i] && argv[i][0] == '-')
	{
		x = 0;
		while (argv[i][++x])
		{
			if (!ft_strchr("pqrs", argv[i][x]))
				return (dis_error(argv[1], FLAG_ERROR, argv[i][x], 0));
			else if (argv[i][x] == 'p')
				initiate_p(ssl, argv[1]);
			else if (argv[i][x] == 'q')
				ssl->flag |= SSL_Q;
			else if (argv[i][x] == 'r')
				ssl->flag |= SSL_R;
			else if (argv[i][x] == 's')
			{
				i = allocate_sflag(argv, ssl, i, x);
				break ;
			}
		}
	}
	return (i);
}

static int		read_msg(char **argv, t_ssl *ssl, int i)
{
	struct stat		buff;
	int				fd;

	(!(ssl->p_flg) && !argv[i] && !(ssl->flag & SSL_S)) &&
		mini_gnl(ssl, argv[1]);
	while (argv[i] && i != 1)
	{
		fd = open(argv[i], O_RDONLY);
		if (fd == -1 && (errno == EACCES))
			return (dis_error(argv[1], NO_PERM, 0, argv[i]));
		else if (fd == -1)
			return (dis_error(argv[1], NO_FILE, 0, argv[i]));
		else if (fstat(fd, &buff) == -1)
			return (dis_error(argv[1], NO_PERM, 0, argv[i]));
		else if (S_ISDIR(buff.st_mode))
			return (dis_error(argv[1], IS_DIR, 0, argv[i]));
		ssl->msg = ft_strnew(buff.st_size);
		read(fd, ssl->msg, buff.st_size);
		ssl->name = ft_strdup(argv[i]);
		close(fd);
		hash_calculate(ssl, argv[1]);
		del_str(ssl);
		i++;
	}
	return (1);
}

int				main(int argc, char **argv)
{
	t_ssl	ssl;
	int		i;

	ft_bzero(&ssl, sizeof(t_ssl));
	if (argc == 1)
		return (ssl_stdin(&ssl));
	if (!check_error(argv[1]))
		return (0);
	if (iscpc(argv[1]))
		return (ssl_cpcverify(argc, argv));
	else if ((i = collect_flags(argv, &ssl)) == 0)
		return (0);
	if (!read_msg(argv, &ssl, i))
		return (0);
	return (1);
}
