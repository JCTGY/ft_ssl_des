/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/16 18:09:02 by jchiang-          #+#    #+#             */
/*   Updated: 2019/05/21 19:17:56 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

/*
** Md5 & sha256
*/

# include "../libft/includes/libft.h"
# include "../libft/includes/ft_printf.h"
# include <sys/stat.h>
# include <fcntl.h>
# include <errno.h>

# define FLAG_ERROR		(1 << 1)
# define S_NO_ARG		(1 << 2)
# define NO_FILE		(1 << 3)
# define NO_PERM		(1 << 4)
# define IS_DIR			(1 << 5)

# define SSL_P			(1 << 0)
# define SSL_S			(1 << 1)
# define SSL_R			(1 << 2)
# define SSL_Q			(1 << 3)
# define SSL_ST			(1 << 4)
# define SSL_PP			(1 << 5)

# define W_NOFILE		1
# define W_UKNOW		2
# define N_BASE64		3

# define BA64_D			1
# define BA64_E			2

typedef struct			s_ssl
{
	int					flag;
	int					p_flg;
	char				*msg;
	char				*name;
}						t_ssl;

typedef struct			s_ba64
{
	int					aoe;
	char				*key;
	char				*iv;
	char				*salt;
	char				*ifd;
	char				*ofd;
	char				*msg;
	char				*data;
}						t_ba64;

typedef struct			s_hash
{
	char				*hash;
	int					(*func)(unsigned char *, size_t, t_ssl *);
}						t_hash;

int						initiate_p(t_ssl *ssl, char *hash);
int						check_error(char *argv);
int						ismdc(char *argv);
int						iscpc(char *argv);
int						dis_error(char *tssl, int error, char flag, char *file);
int						ba64_error(char *name, int error);
int						mini_gnl(t_ssl *ssl, char *hash);
int						hash_calculate(t_ssl *ssl, char *hash);
int						ssl_cpcverify(int ac, char **av);
int						ssl_md5_init(uint8_t *msg, size_t len, t_ssl *ssl);
int						ssl_sha256_init(uint8_t *msg, size_t len, t_ssl *ssl);
int						ssl_sha224_init(uint8_t *msg, size_t len, t_ssl *ssl);
int						ssl_sha384_init(uint8_t *msg, size_t len, t_ssl *ssl);
int						ssl_sha512_init(uint8_t *msg, size_t len, t_ssl *ssl);
int						ssl_base64(int ac, char **av);
int						ssl_base64_std(t_ba64 *ba);
int						ssl_base64_algo(t_ba64 *ba);
int						ssl_des_flag(t_ba64 *ba, int ac, char **av, int i);
void					del_str(t_ssl *ssl);
void					display_usage(void);
void					ssl_free_ba(t_ba64 *ba);

#endif
