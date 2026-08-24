.PHONY: help test lint types check demo clean install

PY ?= python3
export PYTHONPATH := src

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t -s "$$(printf '\t')"

install:  ## install the package in editable mode, with dev extras
	$(PY) -m pip install -e '.[dev]'

test:  ## run the full test suite (no network, no fixtures on disk)
	$(PY) -m unittest discover -s tests -t . -q

lint:  ## ruff
	ruff check src tests conftest.py

types:  ## mypy
	mypy src

check: lint types test  ## everything CI would run

demo:  ## build a synthetic match and produce reports for it in demo/
	$(PY) scripts/make_demo.py demo
	$(PY) -m sami.cli match demo/archives/*.zip --schedule demo/schedule.json \
		--custody demo/custody.jsonl -o demo/report --redacted || true
	@echo "open demo/report/index.html"

clean:
	rm -rf demo build dist .mypy_cache .ruff_cache **/__pycache__
