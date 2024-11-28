# TODO write a description for this script
# @author NathanSnail
# @category _Custom
# @keybinding
# @menupath
# @toolbar

import ghidra
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.app.script import GhidraState
from ghidra.app.util import NamespaceUtils
from ghidra.app.util.cparser.C import CParser
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address
from ghidra.program.model.data import (
	ArrayDataType,
	DataTypeConflictHandler,
	DataTypeManager,
	FunctionDefinition,
	FunctionDefinitionDataType,
	StructureDataType,
)
from ghidra.program.model.listing import Program
from ghidra.program.model.symbol import SourceType, SymbolTable, SymbolType


def log(x):
	print(type(x), x)


def get_state():
	# type: () -> GhidraState
	return getState()


def get_addr():
	# type: () -> Address
	return currentAddress


def hex_n(n):
	if n[0:2] == "0x":
		num = int(n, 16)
	else:
		num = int(n)
	return num


state = get_state()
addr = get_addr()
program = state.getCurrentProgram()
listing = program.getListing()
dman = program.getDataTypeManager()
fpapi = FlatProgramAPI(program)
fdapi = FlatDecompilerAPI(fpapi)
fman = program.getFunctionManager()
symt = program.getSymbolTable()

print(
	[
		runCommand(ApplyFunctionSignatureCmd(y.getAddress(), x, SourceType.ANALYSIS))
		for x, y in [
			(dman.getDataType("primordialis.exe/lua.h/functions/" + x.getName()), x)
			for x in symt.getAllSymbols(True)
			if x.getParentNamespace().getName() == "LUA51.DLL"
			and x.getSymbolType() == SymbolType.FUNCTION
			# if x.getSymbolType() == SymbolType.NAMESPACE
		]
		if x is not None and isinstance(x, FunctionDefinition)
	]
)
