# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -I./includes
LDFLAGS = -lpcap -lpthread

# Directories
SRC_DIR = src
OBJ_DIR = obj

# Source files
SRCS = $(wildcard $(SRC_DIR)/core/*.c) \
       $(wildcard $(SRC_DIR)/network/*.c) \
       $(wildcard $(SRC_DIR)/utils/*.c)

# Object files
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Target executable
NAME = ft_nmap

# Rules
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