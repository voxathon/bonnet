VENV_PYTHON := .venv/bin/python3
UV := uv
CLANG := clang
CYTHON := .venv/bin/cython

PYTHON_INCLUDE := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))")
PYTHON_LIBDIR := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
PYTHON_LDLIBRARY := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LDLIBRARY'))")

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || echo "")
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

MODULES := orm ame ume crypto config conman keibatsu __init

PYTHON_LIBNAME := $(patsubst lib%,%,$(basename $(PYTHON_LDLIBRARY)))

CFLAGS := -O3 -I$(PYTHON_INCLUDE) $(OPENSSL_CFLAGS)
LDFLAGS := -L$(PYTHON_LIBDIR) -l$(PYTHON_LIBNAME) $(OPENSSL_LIBS) -Wl,-rpath,$(PYTHON_LIBDIR)

.PHONY: all clean install pyinstaller

all: $(BIN_DIR)/bonnet

pyinstaller: $(BUILD_DIR)/bonnet.so $(BUILD_DIR)/orm.so $(BUILD_DIR)/ame.so $(BUILD_DIR)/ume.so $(BUILD_DIR)/crypto.so $(BUILD_DIR)/config.so $(BUILD_DIR)/conman.so $(BUILD_DIR)/keibatsu.so $(BUILD_DIR)/__init.so | $(BIN_DIR)
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

$(BUILD_DIR)/crypto.c: $(SRC_DIR)/crypto.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/config.c: $(SRC_DIR)/config.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/conman.c: $(SRC_DIR)/conman.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/keibatsu.c: $(SRC_DIR)/keibatsu.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/__init.so: $(BUILD_DIR)/__init.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/ame.so: $(BUILD_DIR)/ame.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/orm.so: $(BUILD_DIR)/orm.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/ume.so: $(BUILD_DIR)/ume.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/crypto.so: $(BUILD_DIR)/crypto.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/config.so: $(BUILD_DIR)/config.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/conman.so: $(BUILD_DIR)/conman.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/keibatsu.so: $(BUILD_DIR)/keibatsu.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/bonnet.so: $(BUILD_DIR)/bonnet.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

$(BIN_DIR)/bonnet: $(BUILD_DIR)/bonnet_embed.c $(BUILD_DIR)/orm.so $(BUILD_DIR)/ame.so $(BUILD_DIR)/ume.so $(BUILD_DIR)/crypto.so $(BUILD_DIR)/config.so $(BUILD_DIR)/conman.so $(BUILD_DIR)/keibatsu.so $(BUILD_DIR)/__init.so | $(BIN_DIR)
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
