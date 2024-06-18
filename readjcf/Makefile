COURSE  = /clear/www/htdocs/comp321

CC      = cc
CFLAGS  = -std=gnu11 -Wall -Wextra -Werror -g -O2
LDLIBS  = -lnsl -lpthread -lrt

PROG    = readjcf
OBJS    = readjcf.o csapp.o

all: ${PROG}

${PROG}: ${OBJS}
	${CC} ${CFLAGS} -o ${PROG} ${OBJS} ${LDLIBS}

csapp.o: ${COURSE}/src/csapp.c ${COURSE}/include/csapp.h
	${CC} ${CFLAGS} -I${COURSE}/include -c $< 

readjcf.o: readjcf.c ${COURSE}/include/csapp.h
	${CC} ${CFLAGS} -I${COURSE}/include -c $< 

clean:
	${RM} *.o ${PROG} core.[1-9]*

.PHONY: clean
