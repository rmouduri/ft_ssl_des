SRCS		=	src/ft_dprintf.c	\
				src/ft_atoi.c	\
				src/ft_strlen.c	\
				src/ft_isdigit.c	\
				src/write_char.c	\
				src/write_int.c	\
				src/char_conversions.c	\
				src/int_conversions.c	\
				src/uint_conversions.c	\
				src/ptr_conversions.c	\
				src/percent_conv_write.c	\
				src/fill_struct.c	\
				src/write_uint.c	\
				src/format_incrementation.c

INCLUDES	=	./include

OBJS		=	${SRCS:.c=.o}

OBJS_BONUS	=	${SRCS_BONUS:.c=.o}

NAME		=	libftprintf.a

CFLAGS		=	-Wall -Wextra -Werror

CC			=	gcc

RM			=	rm -f

.c.o:
				${CC} ${CFLAGS} -I${INCLUDES} -c $< -o ${<:.c=.o}

${NAME}:		${OBJS}
				ar rc ${NAME} ${OBJS}

all:			${NAME}

bonus:			${NAME}

clean:
				${RM} ${OBJS} ${OBJS_BONUS}

fclean:			clean
				${RM} ${NAME}

re:				fclean all

.PHONY:			all clean fclean re
