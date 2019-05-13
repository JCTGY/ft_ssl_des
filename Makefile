NAME = ft_ssl

SRC_DIR = src/
OBJ_DIR = obj/
LIBFT_DIR = libft/

CFLAG = -Wall -Wextra -Werror

INC = -Iincludes

ALL_SRC =  ft_ssl.c \
		   ssl_help.c \
		   ssl_calculate.c \
		   ssl_md5.c \
		   ssl_md5_help.c \
		   ssl_sha256.c \
		   ssl_sha224.c \
		   ssl_sha256_help.c \
		   ssl_sha512.c \
		   ssl_sha384.c \
		   ssl_sha512_help.c \
		   ssl_sha_print.c \

SRC = $(addprefix $(SRC_DIR), $(ALL_SRC))
OBJ = $(addprefix $(OBJ_DIR), $(ALL_SRC:.c=.o))

all: $(NAME)

$(NAME): $(OBJ)
	make -C $(LIBFT_DIR)
	gcc $(CFLAG) $(OBJ) $(INC) -L $(LIBFT_DIR) -lft -o $(NAME)

$(OBJ_DIR)%.o: $(SRC_DIR)%.c
	mkdir -p obj
	gcc -c $(CFLAG) $(INC) $< -o $@

clean:
	make -C $(LIBFT_DIR)/ clean
	/bin/rm -rf $(OBJ_DIR)

fclean: clean
	make -C $(LIBFT_DIR)/ fclean
	/bin/rm -rf $(NAME)

re: fclean all

.PHONY: all, clean, fclean, re
