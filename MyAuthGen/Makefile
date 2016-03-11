CC=gcc

ifeq ($(shell uname), Linux)
	USBFLAGS = `libusb-config --cflags`
	USBLIBS = `libusb-config --libs`
	EXE_SUFFIX =
	OSFLAG = -D LINUX
else ifeq ($(shell uname), Darwin)
	USBFLAGS = `libusb-config --cflags`
	USBLIBS = `libusb-config --libs`
	EXE_SUFFIX =
	OSFLAG = -D LINUX
else
	USBFLAGS = -I \include
	USBLIBS = -L \lib -lusb
	EXE_SUFFIX = .exe
	OSFLAG = -D WIN
endif

LIBS    = $(USBLIBS) -lcrypto -ldl
INCLUDE = library
CFLAGS  = $(USBFLAGS) $(LIBS) -I$(INCLUDE) -O -g $(OSFLAG)

LWLIBS = littleWire littleWire_util littleWire_servo opendevice spi mfrc522
SRCS = MyAuthGen

.PHONY:	clean library docs

all: library $(SRCS)

library: $(LWLIBS)

$(LWLIBS):
	@echo Building library: $@...
	$(CC) $(CFLAGS) -c library/$@.c 

$(SRCS): $(addsuffix .o, $(LWLIBS))
	@echo Building execurable: $@...
	$(CC) $(CFLAGS) -o $@$(EXE_SUFFIX) src/$@.c $^ $(LIBS)

docs:
	doxygen ./docs/doxygen.conf
	cd ./docs/latex/; make all

clean:
	rm -rf $(SRCS)$(EXE_SUFFIX) *.o *.exe *.dSYM docs/html docs/latex


