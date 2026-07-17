UV := uv
SRC_DIR := src
BIN_DIR := bin

.PHONY: all clean install pyinstaller test run

all: run

run:
	PYTHONPATH=$(SRC_DIR) $(UV) run python $(SRC_DIR)/app/main.py

test:
	PYTHONPATH=$(SRC_DIR) $(UV) run pytest tests/ -v

pyinstaller:
	PYTHONPATH=$(SRC_DIR) $(UV) run pyinstaller bonnet.spec --distpath $(BIN_DIR) --workpath build/pyi

clean:
	rm -rf build/pyi $(BIN_DIR) dist

install: pyinstaller
	cp $(BIN_DIR)/bonnet ./bonnet

uv-test:
	PYTHONPATH=$(SRC_DIR) $(UV) run pytest tests/ -v
