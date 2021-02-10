CC = gcc -Os -Wall
M0CC = arm-none-eabi-gcc -c -mcpu=cortex-m0plus
M4CC = arm-none-eabi-gcc -c -mcpu=cortex-m4
AR = arm-none-eabi-ar rc
CFLAGS = -Os -Wall -fshort-wchar -ffunction-sections -fdata-sections

.PHONY: help all libs clean

help:
	@echo "make test | libs | all | clean"

all: libs test

libs: libqdsv_m0.a libqdsv_m4.a

libqdsv_m0.a: qdsv_m0.o supp_m0.o
	$(AR) $@ $^
qdsv_m0.o: qdsv.c fe1271.inc qdsv.h supp.h
	$(M0CC) $(CFLAGS) -o $@ $(filter %.c, $^)
supp_m0.o: supp.c supp.h
	$(M0CC) $(CFLAGS) -o $@ $(filter %.c, $^)

libqdsv_m4.a: qdsv_m4.o supp_m4.o
	$(AR) $@ $^
qdsv_m4.o: qdsv.c fe1271.inc qdsv.h supp.h
	$(M4CC) $(CFLAGS) -o $@ $(filter %.c, $^)
supp_m4.o: supp.c supp.h
	$(M4CC) $(CFLAGS) -o $@ $(filter %.c, $^)

test: main.c qdsv.c supp.c qdsv.h supp.h
	$(CC) -DCONF_QDSA_FULL -o $@ $(filter %.c, $^)

clean:
	-rm -f *.o *.a test test.exe

# vim: set syn=make noet ts=8 tw=80:
