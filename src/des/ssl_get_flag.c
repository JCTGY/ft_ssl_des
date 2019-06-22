/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_get_flag.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/21 19:25:04 by jchiang-          #+#    #+#             */
/*   Updated: 2019/06/21 20:22:33 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static int		ssl_stdin_key(t_ba64 *ba)
{
	char		pass_veri[PASS_MAX];
	char		*pass;

	if (ba->aoe == BA64_E || !ba->aoe)
	{
		ft_printf("enter %s encryption password", ba->cmd);
		pass = getpass(":");
		ft_strcpy(ba->skey, pass);
		ft_printf("Verifying - enter %s encryption password", ba->cmd);
		pass = getpass(":");
		ft_strcpy(pass_veri, pass);
		if (ft_strcmp(ba->skey, pass_veri))
		{
			ft_printf("Verify failure\nbad password read\n");
			return (0);
		}
	}
	else if (ba->aoe == BA64_D)
	{
		ft_printf("enter %s encryption password", ba->cmd);
		pass = getpass(":");
		ft_strcpy(ba->skey, pass);
	}
	return (1);
}

static int		check_hex_value(char *name, char *hex)
{
	int		i;

	if (ft_strlen(hex) > 16)
		return (dis_error(NULL, H_TOLONG, 0, name));
	i = -1;
	while (hex[++i])
	{
		if (hex[i] >= 'a' && hex[i] <= 'z')
			hex[i] = hex[i] - 32;
	}
	i = -1;
	while (hex[++i])
	{
		if ((hex[i] < '0' || hex[i] > '9') &&
				(hex[i] < 'A' || hex[i] > 'F'))
			return (dis_error(NULL, H_NOVAL, 0, name));
	}
	return (1);
}

static int		get_ssl_arg(t_ba64 *ba, char **av, int *i)
{
	if (!av[*i + 1])
		return (ba64_error(av[*i], W_NOFILE));
	if (ft_strchr("vks", av[*i][1]))
	{
		if (!(check_hex_value(av[*i], av[*i + 1])))
			return (0);
	}
	if (!ft_strcmp(av[*i], "-i"))
		ba->ifd = av[++*i];
	else if (!ft_strcmp(av[*i], "-o"))
		ba->ofd = av[++*i];
	else if (!ft_strcmp(av[*i], "-v"))
		ba->iv = (uint8_t *)av[++*i];
	else if (!ft_strcmp(av[*i], "-k"))
		ba->key = (uint8_t *)av[++*i];
	else if (!ft_strcmp(av[*i], "-s"))
		ba->salt = (uint8_t *)av[++*i];
	else if (!ft_strcmp(av[*i], "-p"))
	{
		ft_strcpy(ba->skey, av[++*i]);
		ba->pflag = BA64_P;
	}
	return (1);
}

int				ssl_des_flag(t_ba64 *ba, int ac, char **av, int i)
{
	ba->cmd = av[1];
	while (++i < ac)
	{
		if (av[i][0] == '-' && ft_strchr("iovksp", av[i][1]) && !av[i][2])
		{
			if (!get_ssl_arg(ba, av, &i))
				return (0);
		}
		else if (!(ft_strcmp(av[i], "-d")))
			ba->aoe = BA64_D;
		else if (!(ft_strcmp(av[i], "-e")))
			ba->aoe = BA64_E;
		else if (!(ft_strcmp(av[i], "-a")))
			ba->a = BA64_A;
		else
			return (ba64_error(av[i], W_UKNOW));
	}
	if ((ba->key == NULL || !ft_strcmp(ba->cmd, "des3") ||
				!ft_strcmp(ba->cmd, "des3_ecb") ||
				!ft_strcmp(ba->cmd, "des3-cbc")) && ba->pflag != BA64_P)
	{
		if (!ssl_stdin_key(ba))
			return (0);
	}
	return (1);
}
