#!/bin/sh -x
PYTHONPATH=. pytest --pdb --pdbcls=IPython.terminal.debugger:Pdb -rA -s -v -x 
