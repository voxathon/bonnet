UV := uv

.PHONY: all clean test test-all run

all: run

run:
	$(UV) run python src/app/main.py

test:
	$(UV) run pytest tests/ -n auto -m "not slow" -v

test-all:
	$(UV) run pytest tests/ -n auto -v

clean:
	rm -rf build/ dist/ .pytest_cache/ .pytest_tmp/
