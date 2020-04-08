SHELL=/bin/bash -e

help:
	@echo - make coverage
	@echo - make test
	@echo - make typecheck
	@echo - make lint
	@echo - make release
	@echo - make clean

coverage:
	python3 -m coverage run --source=securid test.py && python3 -m coverage report -m

test:
	python3 setup.py test

typecheck:
	mypy --strict --no-warn-unused-ignores securid

lint:
	python setup.py flake8

release:
	python ./setup.py bdist_wheel
	cd docs; $(MAKE) html

clean:
	-rm -rf build dist
	-rm -rf *.egg-info

