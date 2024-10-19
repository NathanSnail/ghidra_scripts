# TODO write a description for this script
# @author
# @category _Custom
# @keybinding
# @menupath
# @toolbar

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


def get_state():
	# type: () -> GhidraState
	return getState()


def as_struct(x):
	# type: (DataType) -> StructureDataType
	return x


def get_addr():
	# type: () -> Address
	return currentAddress


state = get_state()
program = state.getCurrentProgram()
fpapi = FlatProgramAPI(program)
fdapi = FlatDecompilerAPI(fpapi)
addr = get_addr()

for x in program.referenceManager.getReferencesTo(addr):
	fun = fpapi.getFunctionContaining(x.fromAddress)
	src = fdapi.decompile(fun)
	name = src.split("::RTTI")[0].split("&")[-1]
	# if name == "WorldStateComponent":
	# print(src, x.fromAddress)
	if name[-9:] != "Component" or '"class"' not in src:
		continue
	print(name)
	refs = program.referenceManager.getReferencesTo(fun.entryPoint)
	for ref in refs:
		print(ref)

