# include config file
CONFIG ?= .config
-include $(CONFIG)
CFLAGSORIG := $(CFLAGS)
-include $(DOVECOT)/dovecot-config
INSTALLDIR ?= $(moduledir)/imap
# Kill CFLAGS from dovecot-config
CFLAGS := $(CFLAGSORIG)

# includes/flags we need for building a dovecot plugin
INCS += -DHAVE_CONFIG_H
INCS += -I$(DOVECOT)/
INCS += -I$(DOVECOT)/src/
INCS += -I$(DOVECOT)/src/lib/
INCS += -I$(DOVECOT)/src/lib-storage/
INCS += -I$(DOVECOT)/src/lib-mail/
INCS += -I$(DOVECOT)/src/lib-imap/
INCS += -I$(DOVECOT)/src/lib-dict/
INCS += -I$(DOVECOT)/src/lib-index/
INCS += -I$(DOVECOT)/src/imap/

# output name
LIBRARY_NAME ?= lib90_$(PLUGINNAME)_plugin.so

# debug rules
ifeq ("$(DEBUG)", "stderr")
CFLAGS += -DCONFIG_DEBUG -DDEBUG_STDERR
objs += debug.o
else 
ifeq ("$(DEBUG)", "syslog")
CFLAGS += -DCONFIG_DEBUG -DDEBUG_SYSLOG
objs += debug.o
endif
endif

ifeq ("$(DEBUG_VERBOSE)", "1")
CFLAGS += -DCONFIG_DEBUG_VERBOSE
endif

# backend error check
ifeq ("$(BACKEND)", "")
error: verify_config
	@echo "Error! no backend configured"
	@false
endif

# per-backend rules
ifeq ("$(BACKEND)", "dspam-exec")
objs += signature.o
endif
ifeq ("$(BACKEND)", "signature-log")
objs += signature.o
endif
ifeq ("$(BACKEND)", "crm114-exec")
objs += signature.o
endif

# main make rules
CFLAGS += -fPIC -shared -Wall -Wextra -DPLUGINNAME=$(PLUGINNAME)
CC ?= cc
HOSTCC ?= cc

objs += antispam-plugin.o antispam-storage.o $(BACKEND).o

all: verify_config $(LIBRARY_NAME)

antispam-storage.o: antispam-storage.c antispam-storage-*.c $(CONFIG) antispam-plugin.h dovecot-version.h
	$(CC) -c $(CFLAGS) $(INCS) -o $@ $<

%.o:	%.c $(CONFIG) antispam-plugin.h dovecot-version.h antispam-version.h
	$(CC) -c $(CFLAGS) $(INCS) -o $@ $<

$(LIBRARY_NAME): $(objs)
	$(CC) $(CFLAGS) $(INCS) $(objs) -o $(LIBRARY_NAME) $(LDFLAGS)

dovecot-version: dovecot-version.c $(CONFIG)
	$(HOSTCC) $(INCS) -o dovecot-version dovecot-version.c

dovecot-version.h: dovecot-version
	./dovecot-version > dovecot-version.h

antispam-version.h: version.sh
	./version.sh > antispam-version.h

clean:
	rm -f *.so *.o *~ dovecot-version dovecot-version.h antispam-version.h

install: all
	install -o $(USER) -g $(GROUP) -m 0755 $(LIBRARY_NAME) $(INSTALLDIR)/

verify_config:
	@if [ ! -r $(CONFIG) ]; then \
		echo -e "\nBuilding the plugin requires a configuration file"; \
		echo -e $(CONFIG)'. Copy defconfig ("cp defconfig' $(CONFIG)'")' ; \
		echo -e "to create an example configuration.\n"; \
		exit 1; \
	fi
