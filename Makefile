SHELL=/bin/bash -e

help:
	@echo - make coverage
	@echo - make test
	@echo - make typecheck
	@echo - make lint
	@echo - make release
	@echo - make clean
	@echo - make doc

coverage:
	python3 -m coverage run --source=securid test.py && python3 -m coverage report -m

test:
	python3 setup.py test

typecheck:
	mypy --strict --no-warn-unused-ignores securid

lint:
	python3 setup.py flake8

release:
	python3 ./setup.py bdist_wheel
	cd docs; $(MAKE) html

clean:
	-rm -rf build dist
	-rm -rf *.egg-info

doc:
	cd docs; $(MAKE) html
