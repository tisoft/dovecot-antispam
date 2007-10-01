# include config file
-include .config

# includes/flags we need for building a dovecot plugin
CFLAGS += -DHAVE_CONFIG_H
CFLAGS += -I$(DOVECOT)/
CFLAGS += -I$(DOVECOT)/src/
CFLAGS += -I$(DOVECOT)/src/lib/
CFLAGS += -I$(DOVECOT)/src/lib-storage/
CFLAGS += -I$(DOVECOT)/src/lib-mail/
CFLAGS += -I$(DOVECOT)/src/lib-imap/
CFLAGS += -I$(DOVECOT)/src/lib-dict/
CFLAGS += -I$(DOVECOT)/src/imap/

# output name
PLUGIN_NAME ?= lib90_antispam_plugin.so

# debug rules
ifeq ("$(DEBUG)", "stderr")
CFLAGS += -DCONFIG_DEBUG -DDEBUG_STDERR
objs += debug.o
else ifeq ("$(DEBUG)", "syslog")
CFLAGS += -DCONFIG_DEBUG -DDEBUG_SYSLOG
objs += debug.o
endif

# dovecot version rules
objs += antispam-storage-$(DOVECOT_VERSION).o
ifeq ("$(DOVECOT_VERSION)", "1.0")
CFLAGS += -Dstr_array_length=strarray_length
CFLAGS += "-Dmempool_unref(x)=pool_unref(*(x))"
else
CFLAGS += "-Dmempool_unref(x)=pool_unref(x)"
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
CFLAGS += -fPIC -shared -Wall
CC ?= "gcc"

objs += antispam-plugin.o $(BACKEND).o
ALL = plugin

all: verify_config $(ALL)

%.o:	%.c .config antispam-plugin.h
	$(CC) -c $(CFLAGS) -o $@ $<

plugin: $(objs)
	$(CC) $(CFLAGS) $(objs) -o $(PLUGIN_NAME) $(LDFLAGS)

clean:
	rm -f $(PLUGIN_NAME) *.o *~

install: all
	install -o root -g root -m 0660 $(PLUGIN_NAME) $(INSTALLDIR)/

verify_config:
	@if [ ! -r .config ]; then \
		echo -e "\nBuilding the plugin requires a configuration file"; \
		echo -e '(.config). Copy defconfig ("cp defconfig .config")' ; \
		echo -e "to create an example configuration.\n"; \
		exit 1; \
	fi
