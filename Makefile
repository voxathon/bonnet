UV := uv

.PHONY: all clean test test-all run

all: run

run:
	$(UV) run python -m bonnet.app.main

test:
	$(UV) run pytest tests/ -n auto -m "not slow" -v

test-all:
	$(UV) run pytest tests/ -n auto -v

clean:
	$(UV) run python -c "import shutil; [shutil.rmtree(p, ignore_errors=True) for p in ('build', 'dist', '.pytest_cache', '.pytest_tmp')]"
