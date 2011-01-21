CC = gcc
LIB = -ldl
INCLUDE_DIR = ../include
ATOKEN_CC = $(CC) $(CC_DEBUG) -fPIC -g -Wall -c $(LIB) -I$(INCLUDE_DIR)
OBJS = atoken.o atoken-crypto.o atoken-keys.o

all: $(OBJS)

atoken.o: $(INCLUDE_DIR)/atoken.h atoken.c
	$(ATOKEN_CC) atoken.c

atoken-crypto.o: $(INCLUDE_DIR)/atoken.h atoken-crypto.c
	$(ATOKEN_CC) atoken-crypto.c

atoken-keys.o: $(INCLUDE_DIR)/atoken.h atoken-keys.c
	$(ATOKEN_CC) atoken-keys.c

clean:
	-rm *.o
