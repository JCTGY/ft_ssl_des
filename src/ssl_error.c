/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_error.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/16 09:30:04 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/17 19:19:57 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int				ismdc(char *argv)
{
	if (ft_strcmp(argv, "md5") && ft_strcmp(argv, "sha256")
				&& ft_strcmp(argv, "sha224") && ft_strcmp(argv, "sha512")
				&& ft_strcmp(argv, "sha384"))
		return (0);
	return (1);
}

int				iscpc(char *argv)
{
	if (ft_strcmp(argv, "base64") && ft_strcmp(argv, "des")
				&& ft_strcmp(argv, "des-ecb") && ft_strcmp(argv, "dec-cbc")
				&& ft_strcmp(argv, "des3") && ft_strcmp(argv, "des3-ecb")
				&& ft_strcmp(argv, "des3-cbc"))
		return (0);
	return (1);
}

int				check_error(char *argv)
{
	if (!argv || (!ismdc(argv) && !iscpc(argv)))
	{
		(argv) &&
			ft_printf("ft_ssl: Error: '%s' is an invalid command\n\n", argv);
		ft_printf("Standard commands:\n\n");
		ft_printf("Message Digest commands:\n");
		ft_printf("md5\nsha224\nsha256\nsha384\nsha512\n\n");
		ft_printf("Cipher commands:\n");
		ft_printf("base64\ndes\ndes-ecb\ndes-cbc\ndes3\ndes3-ecb\ndes3-cbc\n");
		return (0);
	}
	return (1);
}

int				dis_error(char *tssl, int error, char flag, char *file)
{
	if (error == FLAG_ERROR)
	{
		ft_printf("%s: illegal option -- %c\n", tssl, flag);
		ft_printf("usage: %s [-pqr] [-s string] [files ...]\n", tssl);
		return (0);
	}
	else if (error == S_NO_ARG)
	{
		ft_printf("%s: option requires an argument -- %c\n", tssl, flag);
		ft_printf("usage: %s [-pqr] [-s string] [files ...]\n", tssl);
		return (0);
	}
	else if (error == NO_FILE)
		ft_printf("%s: %s: No such file or directory\n", tssl, file);
	else if (error == N_BASE64)
		ft_printf("%s is not base64 file\n", file);
	return (0);
}

int				ba64_error(char *name, int error)
{
	if (error == W_NOFILE)
		ft_printf("Missing argument file for %s\n", name);
	else if (error == W_UKNOW)
		ft_printf("Unknow option \"%s\"\n", name);
	display_usage();
	return (0);
}
