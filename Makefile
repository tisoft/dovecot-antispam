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
CFLAGS += -I$(DOVECOT)/src/imap/

# per-backend configuration
ifeq ("$(BACKEND)", "dspam-exec")
CFLAGS += -DBACKEND_WANTS_SIGNATURE=1
# can take a while, check more often
CFLAGS += -DCOPY_CHECK_INTERVAL=10
endif


# debug rules
ifeq ("$(DEBUG)", "stderr")
CFLAGS += -DCONFIG_DEBUG -DDEBUG_STDERR
objs += debug.o
else ifeq ("$(DEBUG)", "syslog")
CFLAGS += -DCONFIG_DEBUG -DDEBUG_SYSLOG
objs += debug.o
endif


# main make rules
CFLAGS += -fPIC -shared -Wall
CC ?= "gcc"

objs += plugin.o $(BACKEND).o
ALL = antispam

all: verify_config $(ALL)

%.o:	%.c .config
	$(CC) -c $(CFLAGS) -o $@ $<

antispam: $(objs)
	$(CC) $(CFLAGS) $(objs) -o $@.so $(LDFLAGS)

clean:
	rm -f *.so *.o *~

verify_config:
	@if [ ! -r .config ]; then \
		echo -e "\nBuilding the plugin requires a configuration file"; \
		echo -e '(.config). Copy defconfig ("cp defconfig .config")' ; \
		echo -e "to create an example configuration.\n"; \
		exit 1; \
	fi
