CC = gcc
CFLAGS =  -I./includes 
LDFLAGS = -lpcap -lpthread -lresolv -lm #-g -fsanitize=address

SRC_DIR = src
OBJ_DIR = obj

SRCS = $(wildcard $(SRC_DIR)/parsing/*.c) \
       $(wildcard $(SRC_DIR)/network/*.c) \
	   $(wildcard $(SRC_DIR)/*.c)

OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

NAME = ft_nmap

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re