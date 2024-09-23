NAME =		ft_ssl

CC =		gcc
CFLAGS =	-Wall -Werror -Wextra -Wunused -g3

FT_DPRINTF_FOLDER	=	src/ft_dprintf
INCLUDES =	-Iinclude -I$(FT_DPRINTF_FOLDER)/include

SRCS_DIR =	src
OBJS_DIR =	.objs

SRCS_FILE =	main.c \
			option.c	\
			error.c	\
			display.c	\
			utils.c	\
			algo/md5.c	\
			algo/sha256.c	\
			algo/base64.c	\
			algo/des.c		\
			algo/pbkdf2.c


OBJ_FILE =	$(SRCS_FILE:.c=.o)

SRCS	=	$(addprefix $(SRCS_DIR)/,$(SRCS_FILE))
OBJS	=	$(addprefix $(OBJS_DIR)/,$(OBJ_FILE))

RM		=	rm -f
RMDIR	=	rmdir

all: $(NAME)

$(NAME): $(OBJS)
	@make -C ${FT_DPRINTF_FOLDER}
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -L$(FT_DPRINTF_FOLDER) -lftprintf -lbsd -o $(NAME)

$(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c | $(OBJS_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJS_DIR):
	mkdir -p $(OBJS_DIR)/algo

clean:
	@make clean -C $(FT_DPRINTF_FOLDER)
	@$(RM) $(OBJS)
	@if [ -d "$(OBJS_DIR)/algo" ]; then rmdir $(OBJS_DIR)/algo; fi
	@if [ -d "$(OBJS_DIR)" ]; then rmdir $(OBJS_DIR); fi

fclean: clean
	@make fclean -C $(FT_DPRINTF_FOLDER)
	@$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re