# TODO write a description for this script
# @author
# @category _Custom
# @keybinding
# @menupath
# @toolbar

from contextlib import contextmanager

import ghidra
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.app.script import GhidraState
from ghidra.app.util.cparser.C import CParser
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address
from ghidra.program.model.data import (
	ArrayDataType,
	DataTypeConflictHandler,
	DataTypeManager,
	StringDataType,
	StructureDataType,
)
from ghidra.program.model.listing import Program
from ghidra.program.model.symbol import SourceType


def get_state():
	# type: () -> GhidraState
	return getState()


state = get_state()
program = state.getCurrentProgram()

fpapi = FlatProgramAPI(program)

fdapi = FlatDecompilerAPI(fpapi)

fn = fpapi.getFunctionContaining(state.currentAddress)
src = fdapi.decompile(fn)
parts = src.split("lua_pushcclosure")[1:]
for k, part in enumerate(parts):
	name = part.split('"')[1]
	fn = part.split(",")[1]
	# print(name, fn)
	fn = fpapi.getGlobalFunctions(fn)
	if len(fn):
		sym = fn[0].getSymbol()
		print(sym, "Lua_" + name)
		sym.setName("Lua_" + name, SourceType.IMPORTED)
