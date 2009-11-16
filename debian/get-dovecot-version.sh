#!/bin/sh
exec sed -n -e 's/#define PACKAGE_VERSION  *"\(.*\)"/\1/p' \
    /usr/include/dovecot/config.h
