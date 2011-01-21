CC = gcc
LIB = -ldl
INCLUDE_DIR = ../include
OOBEE_CC = $(CC) $(CC_DEBUG) -fPIC -g -Wall -c $(LIB) -I$(INCLUDE_DIR)
OBJS = oo-attrs.o oo-bee.o oo-bee-keys.o oo-bee-objs.o oo-bee-crypto.o

all: $(OBJS)

oo-bee.o: $(INCLUDE_DIR)/oo-bee.h $(INCLUDE_DIR)/bee.h oo-attrs.o oo-bee.c
	$(OOBEE_CC) oo-bee.c

oo-bee-keys.o: $(INCLUDE_DIR)/oo-bee.h $(INCLUDE_DIR)/bee.h oo-attrs.o oo-bee.o oo-bee-keys.c
	$(OOBEE_CC) oo-bee-keys.c

oo-bee-objs.o: $(INCLUDE_DIR)/oo-bee.h $(INCLUDE_DIR)/bee.h oo-attrs.o oo-bee-objs.c
	$(OOBEE_CC) oo-bee-objs.c

oo-bee-crypto.o: $(INCLUDE_DIR)/oo-bee.h $(INCLUDE_DIR)/bee.h oo-attrs.o oo-bee-crypto.c
	$(OOBEE_CC) oo-bee-crypto.c

oo-attrs.o: $(INCLUDE_DIR)/oo-bee.h $(INCLUDE_DIR)/bee.h oo-attrs.c
	$(OOBEE_CC) oo-attrs.c 

clean:
	-rm *.o
