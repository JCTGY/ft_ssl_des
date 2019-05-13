/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/27 09:31:49 by jchiang-          #+#    #+#             */
/*   Updated: 2019/01/28 20:37:35 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"

int		find_newline(int fd, char **stack, char **line)
{
	char	*temp;
	int		i;

	i = 0;
	while (stack[fd][i] != '\n' && stack[fd][i] != '\0')
		i++;
	if (stack[fd][i] == '\0')
	{
		*line = ft_strdup(stack[fd]);
		ft_strdel(&stack[fd]);
	}
	else if (stack[fd][i] == '\n')
	{
		*line = ft_strsub(stack[fd], 0, i);
		temp = ft_strdup(stack[fd] + i + 1);
		free(stack[fd]);
		stack[fd] = temp;
	}
	return (1);
}

int		read_line(int fd, char *buff, char **stack)
{
	int		ret;
	char	*temp;

	while ((ret = read(fd, buff, BUFF_SIZE)) > 0)
	{
		buff[ret] = '\0';
		if (stack[fd] == NULL)
			stack[fd] = ft_strnew(1);
		temp = ft_strjoin(stack[fd], buff);
		free(stack[fd]);
		stack[fd] = temp;
		if (ft_strchr(buff, '\n'))
			break ;
	}
	return (ret);
}

int		get_next_line(const int fd, char **line)
{
	static char		*stack[MAX_FILE];
	char			*buff;
	int				ret;

	if (!line || fd < 0 || fd > MAX_FILE || read(fd, stack[fd], 0) < 0 ||
			!(buff = (char *)malloc(sizeof(char) * BUFF_SIZE + 1)))
		return (-1);
	ret = read_line(fd, buff, stack);
	free(buff);
	if (ret == 0 && (stack[fd] == NULL || stack[fd][0] == '\0'))
		return (0);
	if (find_newline(fd, stack, line) == 1)
		return (1);
	return (-1);
}
