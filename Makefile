# MAKEFILE

MOSQUITTO_SRC=/usr/src/mosquitto-1.3.1

CC = gcc

OBJS=auth_plug_pipe.o

CFLAGS = -I$(MOSQUITTO_SRC)/src/
CFLAGS += -I$(MOSQUITTO_SRC)/lib/
CFLAGS += -fPIC -Wall

INCLUDE = -I/usr/include

LDFLAGS = -L/usr/lib
LDFLAGS += -L$(MOSQUITTO_SRC)/lib/


all: auth_plug_pipe.so 

auth_plug_pipe.so : $(OBJS)
	$(CC) -fPIC -shared $(OBJS) -o $@ $(LDFLAGS)

auth_plug_pipe.o: auth_plug_pipe.c Makefile

clean:
	rm *.o *.so
