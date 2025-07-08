PROG=		lltextract
SRCS=		lltextract.c syscallnames.c names.c
SRCS+=		heap.c
MAN=

SYS_DIR=	${.CURDIR}/../../sys
CFLAGS+=	-I${SYS_DIR}

DEBUG=		-g
WARNINGS=	Yes

.include <bsd.prog.mk>
