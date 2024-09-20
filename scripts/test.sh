#!/bin/sh -ex

command -v podman
wd='/work'
podman run      \
	-it           \
	--pull=always \
	--rm          \
	-v .:/"$wd"   \
	registry.opensuse.org/home/crameleon/containers/containers/crameleon/pytest-acl:latest \
	env PYTHONPATH=/"$wd" pytest --pdb --pdbcls=IPython.terminal.debugger:Pdb -rA -s -v -x "$wd"/tests
