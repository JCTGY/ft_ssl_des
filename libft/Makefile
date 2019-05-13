NAME = libft.a

CFLAGS = -Wall -Wextra -Werror

INC = -Iincludes/

SRC_DIR = src/

ALL_SRC  = 	ft_memchr.c \
			ft_memset.c \
			ft_memalloc.c \
			ft_memmove.c \
			ft_memcpy.c \
			ft_memccpy.c \
			ft_memdel.c \
			ft_bzero.c \
			ft_putchar.c \
			ft_putchar_fd.c \
			ft_putstr.c \
			ft_putstr_fd.c \
			ft_putendl.c \
			ft_putendl_fd.c \
			ft_putnbr.c \
			ft_putnbr_fd.c \
			ft_puterror.c \
			ft_strdel.c \
			ft_strclr.c \
			ft_striter.c \
			ft_striteri.c \
			ft_itoa.c \
			ft_strchr.c \
			ft_strrchr.c \
			ft_strcat.c \
			ft_strncat.c \
			ft_strnew.c \
			ft_strstr.c \
			ft_strnstr.c \
			ft_strdup.c \
			ft_strndup.c \
			ft_strmap.c \
			ft_strmapi.c \
			ft_strsub.c \
			ft_strcpy.c \
			ft_strncpy.c \
			ft_strjoin.c \
			ft_strtrim.c \
			ft_strsplit.c \
			ft_atoi.c \
			ft_memcmp.c \
			ft_isupper.c \
			ft_islower.c \
			ft_isalpha.c \
			ft_isdigit.c \
			ft_isalnum.c \
			ft_isascii.c \
			ft_isprint.c \
			ft_tolower.c \
			ft_toupper.c \
			ft_isspace.c \
			ft_strcmp.c \
			ft_strncmp.c \
			ft_strequ.c \
			ft_strnequ.c \
			ft_strlen.c \
			ft_strlcat.c \
			ft_lstnew.c \
			ft_lstdelone.c \
			ft_lstdel.c \
			ft_lstadd.c \
			ft_lstiter.c \
			ft_lstmap.c \
			ft_lstlen.c \
			get_next_line.c \
			printf.c \
	 	 	pr_verify.c \
		 	pr_char.c \
		   	pr_output.c \
		 	pr_integer.c \
		 	pr_uninteger.c \
		 	pr_double.c \
		   	ft_putnstr.c \
		 	ft_putnchar.c \
			ft_putuintmax.c \
		   	ft_count_digit.c \
		 	ft_itoa_base.c \
		 	ft_int_pow.c \

SRC = $(addprefix $(SRC_DIR), $(ALL_SRC))

OBJ = $(ALL_SRC:.c=.o)

.PHONY = all clean fclean re

all: $(NAME)

$(NAME):
	gcc -c $(CFLAGS) $(SRC) $(INC)
	ar rc $(NAME) $(OBJ)
	ranlib $(NAME)
clean:
	/bin/rm -f $(OBJ)
	echo "Remove OBJ file"

fclean: clean
	/bin/rm -f $(NAME)
	echo "remove all"

re: fclean all
