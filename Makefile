NAME = ft_nmap

SRC =	src/main.c \
		src/parsing/parse_args.c \
		src/parsing/parse_ports.c \
		src/parsing/parse_speedup.c \
		src/parsing/parse_scan.c \
		src/parsing/parse_ips.c \

FLAGS =  -Wall -Werror -Wextra
CC = gcc

INC =	includes/ft_nmap.h


OBJ = $(SRC:.c=.o)

all : $(NAME)

$(NAME) : $(OBJ)
	$(CC) $(FLAGS) $(OBJ) -o $(NAME)

%.o : %.c $(INC)
	$(CC) $(FLAGS) -o $@ -c $<

clean :
	rm -f $(OBJ)

fclean : clean
	rm -f $(NAME)

re : fclean all
