# 
# PAM DCE Caching Module
#
# Copyright (c) 2001 Paul B. Henson <henson@acm.org>
#
# See COPYRIGHT file for details
#

CC = gcc
CFLAGS = -I/opt/dce/share/include -fpic -D_REENTRANT -DPIC -D_TS_ERRNO

# uncomment to allow only root (as opposed to root and the credential owner)
# to access the cache
#CFLAGS += -DROOT_ONLY

# uncomment for "broken" IBM DCE implementations
CFLAGS += -DIBM_DCE_ONLY

LIBS = -ldce -lpam -lsocket -lnsl

OBJECTS = pam_dce_cache.o dce_cache.o

all:	pam_dce_cache.so.1

.c.o:
	$(CC) $(CFLAGS) -c $<

pam_dce_cache.so.1: $(OBJECTS)
	$(CC) -o pam_dce_cache.so.1 -G $(OBJECTS) $(LIBS)

install: pam_dce_cache.so.1
	cp pam_dce_cache.so.1 /usr/lib/security/pam_dce_cache.so.1
	chown root:sys /usr/lib/security/pam_dce_cache.so.1
	chmod 755 /usr/lib/security/pam_dce_cache.so.1

clean:
	rm -f *.o *~ pam_dce_cache.so.1
