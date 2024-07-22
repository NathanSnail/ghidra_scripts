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


def get_state():
	# type: () -> GhidraState
	return getState()


state = get_state()
program = state.getCurrentProgram()

fpapi = FlatProgramAPI(program)

fdapi = FlatDecompilerAPI(fpapi)

fn = fpapi.getFunctionContaining(state.currentAddress)
print(fn.name)
src = fdapi.decompile(fn)
print(src)
parts = src.split("GetGlobal")
for k, part in enumerate(parts):
	if k == len(parts) - 1:
		continue
	name = part.split('"')[-2]
	n = parts[k + 1]

	# )
	ty = n.split("(")[0]
	v = n.split("&")[1].split(")")[0]
	addr = None
	if v[:3] == "DAT":
		addr = fpapi.addressFactory.getAddress(v[4:])
	else:
		addrs = fpapi.getSymbols(v, None)
		if len(addrs):
			addr = addrs[0].address
	print(name, ty, v, addr)
	sym = fpapi.createLabel(addr, name, True)
	m = {
		"Bool": "bool",
		"String": "StdString",
		"Int": "int",
		"Float": "float",
		"Double": "double",
	}
	if ty in m.keys() and addr is not None:
		dt = fpapi.getDataTypes(m[ty])[0]
		fpapi.clearListing(addr, addr.add(dt.getLength() - 1))
		fpapi.createData(addr, dt)
