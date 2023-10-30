SHELL=/bin/bash -e

help:
	@echo - make coverage
	@echo - make test
	@echo - make typecheck
	@echo - make lint
	@echo - make release
	@echo - make clean
	@echo - make doc

isort:
	isort --profile black securid tests

black: isort
	black securid tests

coverage:
	pytest --cov --cov-report=term-missing

test:
	pytest

typecheck:
	mypy --strict --no-warn-unused-ignores securid

lint:
	flake8 securid.py securid tests

release:
	python -m build --sdist --wheel
	cd docs; $(MAKE) html

clean:
	-rm -rf build dist
	-rm -rf *.egg-info
	-rm -rf bin lib share pyvenv.cfg

venv:
	python3 -m virtualenv .
	. bin/activate; pip install -Ur requirements.txt
	. bin/activate; pip install -Ur requirements-dev.txt

doc:
	cd docs; $(MAKE) html
