OPENRESTY_PREFIX=/usr/local/openresty-debug

PREFIX ?=          /usr/local
LUA_INCLUDE_DIR ?= $(PREFIX)/include
LUA_LIB_DIR ?=     $(PREFIX)/lib/lua/$(LUA_VERSION)
INSTALL ?= install

.PHONY: all test install

all: ;

install: all
	$(INSTALL) -d $(DESTDIR)/$(LUA_LIB_DIR)/resty
	$(INSTALL) lib/resty/*.lua $(DESTDIR)/$(LUA_LIB_DIR)/resty
	$(INSTALL) -d $(DESTDIR)/$(LUA_LIB_DIR)/resty/crypto
	$(INSTALL) lib/resty/crypto/*.lua $(DESTDIR)/$(LUA_LIB_DIR)/resty/crypto
	$(INSTALL) -d $(DESTDIR)/$(LUA_LIB_DIR)/resty/digest
	$(INSTALL) lib/resty/digest/*.lua $(DESTDIR)/$(LUA_LIB_DIR)/resty/digest
	$(INSTALL) -d $(DESTDIR)/$(LUA_LIB_DIR)/resty/utils
	$(INSTALL) lib/resty/utils/*.lua $(DESTDIR)/$(LUA_LIB_DIR)/resty/utils

test: all
	PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove -I../test-nginx/lib -r t
