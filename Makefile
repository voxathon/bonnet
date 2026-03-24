VENV_PYTHON := .venv/bin/python3
UV := uv
CLANG := gcc
CYTHON := .venv/bin/cython

PYTHON_INCLUDE := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))")
PYTHON_LIBDIR := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
PYTHON_LDLIBRARY := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LDLIBRARY'))")

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || echo "")
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

CYTHON_FILES := $(shell find $(SRC_DIR) -name '*.pyx')
C_FILES := $(patsubst $(SRC_DIR)/%.pyx,$(BUILD_DIR)/%.c,$(CYTHON_FILES))
SO_FILES := $(patsubst $(SRC_DIR)/%.pyx,$(BUILD_DIR)/%.so,$(CYTHON_FILES))

PYTHON_LIBNAME := $(patsubst lib%,%,$(basename $(PYTHON_LDLIBRARY)))

CFLAGS := -O3 -I$(PYTHON_INCLUDE) $(OPENSSL_CFLAGS)
LDFLAGS := -L$(PYTHON_LIBDIR) -l$(PYTHON_LIBNAME) $(OPENSSL_LIBS) -Wl,-rpath,$(PYTHON_LIBDIR)

.PHONY: all clean install pyinstaller

all: $(BIN_DIR)/bonnet

pyinstaller: $(SO_FILES) | $(BIN_DIR)
	@echo "Copying .so files to src for pyinstaller..."
	@cd $(BUILD_DIR) && find . -name '*.so' -exec cp --parents {} ../$(SRC_DIR)/ \;
	PYTHONPATH=src .venv/bin/pyinstaller bonnet.spec --distpath $(BIN_DIR) --workpath build/pyi
	@echo "Cleaning up .so files from src..."
	@cd $(SRC_DIR) && find . -name '*.so' -delete

$(BUILD_DIR):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.c: $(SRC_DIR)/%.pyx | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/app/server_embed.c: $(SRC_DIR)/app/server.pyx | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CYTHON) --embed -3 $< -o $@

$(BUILD_DIR)/%.so: $(BUILD_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@ $(LDFLAGS)

# Main executable target
$(BIN_DIR)/bonnet: $(BUILD_DIR)/app/server_embed.c $(SO_FILES) | $(BIN_DIR)
	$(CLANG) $(CFLAGS) $< -o $@.bin $(LDFLAGS)
	@echo "Copying .so files to bin directory..."
	@cd $(BUILD_DIR) && find . -name '*.so' -exec cp --parents {} ../$(BIN_DIR)/ \;
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
