# @copyright@
# Copyright (c) 2006 - 2017 Teradata
# All rights reserved. Stacki(r) v5.x stacki.com
# https://github.com/Teradata/stacki/blob/master/LICENSE.txt
# @copyright@
#

ROLLROOT	= ../../../..
DEPENDS.DIRS	= files
include $(STACKBUILD)/etc/CCRules.mk

ifeq ($(ROLLVERSION),)
ROLLVERSION = $(RPM_PACKAGE_VERSION)
endif


build:
	echo "Building migration files"

install::
	mkdir -p $(ROOT)/opt/stack/share/migrations/$(ROLL)/
	(cd files ; \
	for x in *.py; do	\
		$(INSTALL) -m444 $$x $(ROOT)/opt/stack/share/migrations/$(ROLL)/ ; \
	done)

