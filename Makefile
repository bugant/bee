CC = gcc
LIB = -ldl
VERSION = 1
MIN_VERSION = 0
RELEASE_VERSION = 0
NAME=libbee.so
LIBNAME=$(NAME).$(VERSION)
LIB_PATH=/usr/lib
CC_LIB = $(CC) -shared -Wl,-soname,$(LIBNAME)
CC_DEBUG_FLAG = -DDEBUG
CC_DEBUG =

ifeq ($(DEBUG), yes)
    CC_DEBUG = $(CC_DEBUG_FLAG)
endif

export CC_DEBUG

build: atoken-build bee-build oo-build

atoken-build:
	cd atoken && $(MAKE)

bee-build:
	cd bee && $(MAKE)

oo-build:
	cd oo-bee && $(MAKE)

#reverse-tests-build:
#	cd reverse-tests && $(MAKE)

lib: build
	$(CC_LIB) -o $(LIBNAME).$(MIN_VERSION).$(RELEASE_VERSION) atoken/*.o bee/*.o oo-bee/*.o

install: lib
	cp $(LIBNAME).$(MIN_VERSION).$(RELEASE_VERSION) $(LIB_PATH)/$(LIBNAME)
	if [ ! -f $(LIB_PATH)/$(NAME) ]; then  ln -s $(LIB_PATH)/$(LIBNAME) $(LIB_PATH)/$(NAME); fi

clean:
	cd atoken && $(MAKE) clean
	cd bee && $(MAKE) clean
	cd oo-bee && $(MAKE) clean
	#cd reverse-tests && $(MAKE) clean
