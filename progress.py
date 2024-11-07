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
from ghidra.program.model.address import Address
from ghidra.program.model.data import (
	ArrayDataType,
	DataTypeConflictHandler,
	DataTypeManager,
	StringDataType,
	StructureDataType,
)
from ghidra.program.model.listing import Program


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
data_type_manager = program.getDataTypeManager()
fpapi = FlatProgramAPI(program)
fdapi = FlatDecompilerAPI(fpapi)

fns = [
	str(x) for x in program.getFunctionManager().getFunctions(True) if "@" not in str(x)
]
done = len([x for x in fns if x[:4] != "FUN_"])
print(
	"Done: %d, Total: %d, Remaining: %d Completion: %.2f%%"
	% (done, len(fns), len(fns) - done, float(done) / len(fns) * 100)
)
