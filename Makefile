# Makefile
# Copyright 2020 by Luke Meyers (lukem1900@gmail.com)
# This program comes with ABSOLUTELY NO WARRANTY.

.PHONY: lint

DLIST:=missing-function-docstring,missing-module-docstring
DLIST:=$(DLIST),missing-class-docstring,too-few-public-methods
DLIST:=$(DLIST),too-many-arguments,too-many-locals,too-many-instance-attributes
DLIST:=$(DLIST),too-many-branches,too-many-statements

lint:
	pep8 urraid.py
	pylint --disable=$(DLIST) \
		--include-naming-hint=y \
		--good-names=fp \
		urraid.py
