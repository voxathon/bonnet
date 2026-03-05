VENV_PYTHON := .venv/bin/python3
UV := uv
CLANG := clang
CYTHON := .venv/bin/cython

PYTHON_INCLUDE := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))")
PYTHON_LIBDIR := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
PYTHON_LDLIBRARY := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LDLIBRARY'))")

OPENSSL_VERSION := $(shell grep '^OPENSSL_VERSION=' .openssl-version 2>/dev/null | cut -d= -f2)
OPENSSL_CACHE := .cache/openssl/$(OPENSSL_VERSION)
OPENSSL_MARKER := $(OPENSSL_CACHE)/.extracted

OPENSSL_SYSTEM_OK := $(shell ./scripts/check-openssl.sh 2>/dev/null || echo "no")

ifeq ($(OPENSSL_SYSTEM_OK),yes)
    OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || echo "")
    OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")
    OPENSSL_DEP :=
else
    OPENSSL_CFLAGS := -I$(OPENSSL_CACHE)/usr/include -I$(OPENSSL_CACHE)/usr/include/x86_64-linux-gnu
    OPENSSL_LIBS := -L$(OPENSSL_CACHE)/usr/lib/x86_64-linux-gnu -lssl -lcrypto -Wl,-rpath,'$$ORIGIN/../.cache/openssl/$(OPENSSL_VERSION)/usr/lib/x86_64-linux-gnu'
    OPENSSL_DEP := $(OPENSSL_MARKER)
endif

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

MODULES := orm ame ume tls __init

PYTHON_LIBNAME := $(patsubst lib%,%,$(basename $(PYTHON_LDLIBRARY)))

CFLAGS := -O3 -I$(PYTHON_INCLUDE) $(OPENSSL_CFLAGS)
LDFLAGS := -L$(PYTHON_LIBDIR) -l$(PYTHON_LIBNAME) $(OPENSSL_LIBS) -Wl,-rpath,$(PYTHON_LIBDIR)

.PHONY: all clean install pyinstaller fetch-openssl

$(OPENSSL_MARKER):
	@echo "System OpenSSL too old or missing. Downloading OpenSSL $(OPENSSL_VERSION)..."
	./scripts/fetch-openssl.sh

fetch-openssl:
	./scripts/fetch-openssl.sh

all: $(BIN_DIR)/bonnet

pyinstaller: $(BUILD_DIR)/bonnet.so $(BUILD_DIR)/orm.so $(BUILD_DIR)/ame.so $(BUILD_DIR)/ume.so $(BUILD_DIR)/tls.so $(BUILD_DIR)/__init.so | $(BIN_DIR)
	cp $(BUILD_DIR)/*.so src/
	PYTHONPATH=src .venv/bin/pyinstaller bonnet.spec --distpath $(BIN_DIR) --workpath build/pyi
	rm -f src/*.so

$(BUILD_DIR):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

$(BUILD_DIR)/bonnet.c: $(SRC_DIR)/bonnet.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/bonnet_embed.c: $(SRC_DIR)/bonnet.pyx | $(BUILD_DIR)
	$(CYTHON) --embed -3 $< -o $@

$(BUILD_DIR)/__init.c: $(SRC_DIR)/__init__.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@



$(BUILD_DIR)/orm.c: $(SRC_DIR)/orm.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/ame.c: $(SRC_DIR)/ame.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/ume.c: $(SRC_DIR)/ume.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/tls.c: $(SRC_DIR)/tls.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/__init.so: $(BUILD_DIR)/__init.c $(OPENSSL_DEP)
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/ame.so: $(BUILD_DIR)/ame.c $(OPENSSL_DEP)
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/orm.so: $(BUILD_DIR)/orm.c $(OPENSSL_DEP)
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/ume.so: $(BUILD_DIR)/ume.c $(OPENSSL_DEP)
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/tls.so: $(BUILD_DIR)/tls.c $(OPENSSL_DEP)
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/bonnet.so: $(BUILD_DIR)/bonnet.c $(OPENSSL_DEP)
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BIN_DIR)/bonnet: $(BUILD_DIR)/bonnet_embed.c $(BUILD_DIR)/orm.so $(BUILD_DIR)/ame.so $(BUILD_DIR)/ume.so $(BUILD_DIR)/tls.so $(BUILD_DIR)/__init.so | $(BIN_DIR)
	$(CLANG) $(CFLAGS) $(BUILD_DIR)/bonnet_embed.c -o $@.bin $(LDFLAGS)
	cp $(BUILD_DIR)/*.so $(BIN_DIR)/
	@printf '#!/bin/bash\nSCRIPT_DIR="$$(cd "$$(dirname "$$0")" && pwd)"\nVENV_DIR="$$(cd "$${SCRIPT_DIR}/.." && pwd)/.venv"\nPYTHONPATH="$${VENV_DIR}/lib/python3.12/site-packages:$${SCRIPT_DIR}"\nexport PYTHONPATH\nexec "$${SCRIPT_DIR}/bonnet.bin" "$$@"\n' > $@
	@chmod +x $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) build/pyi dist build/bonnet.spec

install: all
	install -m 755 $(BIN_DIR)/bonnet /usr/local/bin/bonnet

uv-build:
	$(UV) run make all

uv-clean:
	$(UV) run make clean
