CC = gcc
LIB = -ldl
INCLUDE_DIR = ../include
BEE_CC = $(CC) $(CC_DEBUG) -fPIC -g -Wall -c $(LIB) -I$(INCLUDE_DIR)
OBJS = attrs-utility.o bee.o bee-keys.o bee-objs.o bee-crypto.o bee-info.o

all: $(OBJS)

bee.o: $(INCLUDE_DIR)/atoken.h $(INCLUDE_DIR)/bee.h attrs-utility.o bee.c
	$(BEE_CC) bee.c

bee-keys.o: $(INCLUDE_DIR)/atoken.h $(INCLUDE_DIR)/bee.h attrs-utility.o bee-keys.c
	$(BEE_CC) bee-keys.c

bee-objs.o: $(INCLUDE_DIR)/atoken.h $(INCLUDE_DIR)/bee.h attrs-utility.o bee-objs.c
	$(BEE_CC) bee-objs.c

bee-crypto.o: $(INCLUDE_DIR)/atoken.h $(INCLUDE_DIR)/bee.h attrs-utility.o bee-crypto.c
	$(BEE_CC) bee-crypto.c

bee-info.o: $(INCLUDE_DIR)/atoken.h $(INCLUDE_DIR)/bee.h attrs-utility.o bee-info.c
	$(BEE_CC) bee-info.c

attrs-utility.o: $(INCLUDE_DIR)/atoken.h $(INCLUDE_DIR)/bee.h attrs-utility.c
	$(BEE_CC) attrs-utility.c 

clean:
	-rm *.o
