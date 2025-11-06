# TODO write a description for this script
# @author NathanSnail
# @category _Custom
# @keybinding
# @menupath
# @toolbar

import ghidra
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.app.script import GhidraState
from ghidra.app.util.cparser.C import CParser
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address, GlobalNamespace
from ghidra.program.model.data import (
	ArrayDataType,
	DataTypeConflictHandler,
	DataTypeManager,
	StringDataType,
	StructureDataType,
)
from ghidra.program.model.listing import Program

import re

from ghidra.program.model.symbol import SourceType

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


# Ensure the "Lua" namespace exists (or create it)
lua_ns = symt.getOrCreateNameSpace(program.getGlobalNamespace(), "Lua", SourceType.USER_DEFINED)

pattern = re.compile(r"^Lua_(.*)")

count = 0
for func in fman.getFunctions(True):
    m = pattern.match(func.getName())
    if not m:
        continue

    new_name = m.group(1)
    print(new_name)
    func.setName(new_name, SourceType.USER_DEFINED)
    func.setParentNamespace(lua_ns)
    count += 1

print("Moved {} functions into 'Lua' namespace.".format(count))
