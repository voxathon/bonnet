UV := uv
SRC_DIR := src
BIN_DIR := bin

.PHONY: all clean install pyinstaller test test-all run uv-test

all: run

run:
	PYTHONPATH=$(SRC_DIR) $(UV) run python $(SRC_DIR)/app/main.py

test:
	PYTHONPATH=$(SRC_DIR) $(UV) run pytest tests/ -n auto -m "not slow" -v

pyinstaller:
	PYTHONPATH=$(SRC_DIR) $(UV) run pyinstaller bonnet.spec --distpath $(BIN_DIR) --workpath build/pyi

clean:
	rm -rf build/pyi $(BIN_DIR) dist

install: pyinstaller
	cp $(BIN_DIR)/bonnet ./bonnet

test-all:
	PYTHONPATH=$(SRC_DIR) $(UV) run pytest tests/ -n auto -v

uv-test:
	PYTHONPATH=$(SRC_DIR) $(UV) run pytest tests/ -n auto -m "not slow" -v
