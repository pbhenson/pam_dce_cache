# 
# PAM DCE Caching Module
#
# Copyright (c) 2001 Paul B. Henson <henson@acm.org>
#
# See COPYRIGHT file for details
#

CC = gcc
CFLAGS = -fpic -D_REENTRANT -DPIC -D_TS_ERRNO

LIBS = -ldce -lpam -lsocket -lnsl

OBJECTS = pam_dce_cache.o

all:	pam_dce_cache.so.1

.c.o:
	$(CC) $(CFLAGS) -c $<

pam_dce_cache.so.1: $(OBJECTS)
	$(CC) -o pam_dce_cache.so.1 -G $(OBJECTS) $(LIBS)

install: pam_dce_cache.so.1
	cp pam_dce_cache.so.1 /usr/lib/security/pam_dce_cache.so.1
	chown root:sys /usr/lib/security/pam_dce_cache.so.1
	chmod 755 /usr/lib/security/pam_dce_cache.so.1
	cp S15-15pam_dce_cache /etc/rc3.d/S15-15pam_dce_cache
	chown root:sys /etc/rc3.d/S15-15pam_dce_cache
	chmod 700 /etc/rc3.d/S15-15pam_dce_cache

clean:
	rm -f *.o *~ pam_dce_cache.so.1
