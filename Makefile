VENV_PYTHON := .venv/bin/python3
UV := uv
CLANG := clang
CYTHON := .venv/bin/cython

PYTHON_INCLUDE := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))")
PYTHON_LIBDIR := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
PYTHON_LDLIBRARY := $(shell $(VENV_PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LDLIBRARY'))")

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

MODULES := module1 module2 module3 orm __init

CFLAGS := -O3 -I$(PYTHON_INCLUDE)
LDFLAGS := -L$(PYTHON_LIBDIR) -lpython3.12 -Wl,-rpath,$(PYTHON_LIBDIR)

.PHONY: all clean install

all: $(BIN_DIR)/main

$(BUILD_DIR):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

$(BUILD_DIR)/main.c: $(SRC_DIR)/main.pyx | $(BUILD_DIR)
	$(CYTHON) --embed -3 $< -o $@

$(BUILD_DIR)/__init.c: $(SRC_DIR)/__init__.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/module1.c: $(SRC_DIR)/module1.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/module2.c: $(SRC_DIR)/module2.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/module3.c: $(SRC_DIR)/module3.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/orm.c: $(SRC_DIR)/orm.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/__init.so: $(BUILD_DIR)/__init.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@

$(BUILD_DIR)/module1.so: $(BUILD_DIR)/module1.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@

$(BUILD_DIR)/module2.so: $(BUILD_DIR)/module2.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@

$(BUILD_DIR)/module3.so: $(BUILD_DIR)/module3.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@

$(BUILD_DIR)/orm.so: $(BUILD_DIR)/orm.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@

$(BIN_DIR)/main: $(BUILD_DIR)/main.c $(BUILD_DIR)/module1.so $(BUILD_DIR)/module2.so $(BUILD_DIR)/module3.so $(BUILD_DIR)/orm.so $(BUILD_DIR)/__init.so | $(BIN_DIR)
	$(CLANG) $(CFLAGS) $(BUILD_DIR)/main.c -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

install: all
	install -m 755 $(BIN_DIR)/main /usr/local/bin/bonnet

uv-build:
	$(UV) run make all

uv-clean:
	$(UV) run make clean