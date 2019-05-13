/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstlen.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/13 19:41:23 by jchiang-          #+#    #+#             */
/*   Updated: 2018/12/13 20:15:14 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_lstlen(const t_list *list)
{
	size_t		len;
	t_list		*temp;

	temp = (t_list *)list;
	if (!temp)
		return (0);
	len = 0;
	while (temp)
	{
		temp = temp->next;
		len++;
	}
	return (len);
}
