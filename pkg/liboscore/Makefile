PKG_NAME=liboscore
PKG_URL=https://gitlab.com/oscore/liboscore.git

# liboscore-v0.2.7
PKG_VERSION=d3b6e9d58f8110cd648151cfa78e8a80be4bdf4e
PKG_LICENSE=BSD-3-Clause

include $(RIOTBASE)/pkg/pkg.mk

# CFLAGS += -Wno-type-limits

# # avoid compilation errors when NDEBUG is defined
# CFLAGS += -Wno-unused-parameter

# form 
all:
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/c -f $(CURDIR)/$(PKG_NAME).mk

# all:
# 	$(MAKE) -C $(PKG_SOURCE_DIR) -f $(RIOTBASE)/Makefile.base
