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
from ghidra.program.model.data import (ArrayDataType, DataTypeConflictHandler,
                                       DataTypeManager, StringDataType,
                                       StructureDataType)
from ghidra.program.model.symbol import SourceType


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
data_type_manager = program.getDataTypeManager()
fdapi = FlatDecompilerAPI(fpapi)
addr = get_addr()
entity = data_type_manager.getPointer(
	data_type_manager.getDataType("noita.exe/auto_structs/Entity")
)


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
		ref_fn = fpapi.getFunctionContaining(ref.fromAddress)
		ref_src = fdapi.decompile(ref_fn)
		if (
			"0xf <" in ref_src
			and "MutexBS" in ref_src
			and "ComponentIdentifier" in ref_src
			and "== 0" in ref_src
			and "-1 <" in ref_src
			and " & " not in ref_src
		):
			print("considering", ref_fn.name)
			print(ref_src)
			if (
				"code **" not in ref_src
				and "EntityManger" not in ref_src
				and "0x8000" not in ref_src
			):
				continue
			print(name, "worked")
			prefix = "FirstEnabled" if "0x8000" in ref_src else "First"
			ref_fn.setParentNamespace(fpapi.getNamespace(None, "EntityManager"))
			ref_fn.setName(prefix + name, SourceType.ANALYSIS)
			ref_fn.setReturnType(
				data_type_manager.getPointer(
					data_type_manager.getDataType("noita.exe/" + name)
				),
				SourceType.ANALYSIS,
			)
			param = ref_fn.getParameters()[-1]
			print(param)
			if param.hasStackStorage():
				param.setDataType(
					entity,
					SourceType.ANALYSIS,
				)
