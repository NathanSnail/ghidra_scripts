# TODO write a description for this script
# @author
# @category _Custom
# @keybinding
# @menupath
# @toolbar

import math

import ghidra
from docking.widgets.dialogs import InputDialog
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

data_type_manager = program.getDataTypeManager()


def make_lens(ty):
	itype = data_type_manager.getDataType("/int")
	dtype = data_type_manager.getDataType("/" + ty)
	size = dtype.getLength()
	shift = int(math.ceil(float(size * 2) / 4) * 4) + 4
	print(shift)
	struct = StructureDataType("LensValue<" + ty + ">", shift)
	struct.replaceAtOffset(0, dtype, size, "value", "normal value")
	struct.replaceAtOffset(size, dtype, size, "default", "only on first frame")
	struct.replaceAtOffset(shift - 4, itype, 4, "frame", "should always be -1")
	data_type_manager.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)


make_lens("float")
make_lens("int")
make_lens("bool")
