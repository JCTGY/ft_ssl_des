NAME := ft_ssl

SRC_DIR := src/
MD5_DIR := src/md5/
DES_DIR := src/des/
OBJ_DIR := obj/
LIBFT_DIR = libft/

CFLAG := -Wall -Wextra -Werror

INC := -Iincludes

MAIN_SRC :=	ft_ssl.c \
			ssl_error.c \
			ssl_usage.c \

MD5_SRC :=	ssl_help.c \
			ssl_md5.c \
			ssl_md5_help.c \
			ssl_sha256.c \
			ssl_sha224.c \
			ssl_sha256_help.c \
			ssl_sha512.c \
			ssl_sha384.c \
			ssl_sha512_help.c \
			ssl_sha_print.c \
			ssl_calculate.c \

DES_SRC :=	ssl_des.c \
			ssl_base64.c \
			ssl_cpcverify.c \
			ssl_base64_std.c \
			ssl_base64_algo.c \
			ssl_base64_help.c \
			ssl_get_flag.c \


SRC = $(addprefix $(SRC_DIR), $(MAIN_SRC)) \
	  $(addprefix $(MD5_DIR), $(MD5_SRC)) \
	  $(addprefix $(DES_DIR), $(DES_SRC)) 

OBJ := $(addprefix $(OBJ_DIR), $(MAIN_SRC:.c=.o)) \
	$(addprefix $(OBJ_DIR), $(MD5_SRC:.c=.o)) \
		$(addprefix $(OBJ_DIR), $(DES_SRC:.c=.o))

all: $(NAME)

$(NAME): $(OBJ)
	make -C $(LIBFT_DIR)
	gcc $(CFLAG) $(OBJ) $(INC) -L $(LIBFT_DIR) -lft -o $(NAME)

$(OBJ_DIR)%.o: $(SRC_DIR)%.c
	mkdir -p obj
	gcc -c $(CFLAG) $(INC) $< -o $@

$(OBJ_DIR)%.o: $(MD5_DIR)%.c
	gcc -c $(CFLAG) $(INC) $< -o $@

$(OBJ_DIR)%.o: $(DES_DIR)%.c
	gcc -c $(CFLAG) $(INC) $< -o $@

clean:
	make -C $(LIBFT_DIR)/ clean
	/bin/rm -rf $(OBJ_DIR)

fclean: clean
	make -C $(LIBFT_DIR)/ fclean
	/bin/rm -rf $(NAME)

re: fclean all

.PHONY: all, clean, fclean, re
