#
#   Makefile for building Linux port of BSD's pam_alreadyloggedin module.
#
#   Written by Ilya Evseev using template from pam_mktemp package
#   by Solar Designer and Dmitry Levin.
#
#   stefano 2010-06-15
#

CC = gcc
LD = ld
RM = rm -f
MKDIR = mkdir -p
INSTALL = install
CFLAGS = -Wall -g -O2 -lpam -fPIC -DLINUX_PAM -I. -DBUG_STAT_MISSING -DMKHOMEDIR_HELPER=\"/sbin/mkhomedir_helper_calibre\"

TITLE = pam_mkhomedir_calibre
LIBSHARED = $(TITLE).so
BINARY = mkhomedir_helper_calibre
SHLIBMODE = 700
SECUREDIR = /lib/security
SBINDIR = /sbin
SBINMODE = 755
FAKEROOT =

OBJS = $(TITLE).o
BOBJS = $(BINARY).o

all: $(LIBSHARED) $(BINARY)

$(TITLE).o: $(TITLE).c
	$(CC) -c $(CFLAGS) $<

$(LIBSHARED): $(OBJS)
	$(CC) -shared $(OBJS) -o $@

$(BINARY).o: $(BINARY).c
	$(CC) -c $(CFLAGS) $<

$(BINARY): $(BOBJS)
	$(CC) $(CFLAGS) $(BOBJS) -o $@

install:
	$(MKDIR) $(FAKEROOT)$(SECUREDIR)
	$(INSTALL) -m $(SHLIBMODE) $(LIBSHARED) $(FAKEROOT)$(SECUREDIR)
	$(MKDIR) $(FAKEROOT)$(SBINDIR)
	$(INSTALL) -m $(SBINMODE) $(BINARY) $(FAKEROOT)$(SBINDIR)

uninstall: remove

remove:
	$(RM) $(FAKEROOT)$(SECUREDIR)/$(TITLE).so
	$(RM) $(FAKEROOT)$(SBINDIR)/$(BINARY)

clean:
	$(RM) $(BINARY) $(LIBSHARED) *.o

## EOF ##
