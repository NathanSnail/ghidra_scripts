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
	prenamed = fun.parentNamespace.name
	already_done = prenamed[-9:] == "Component"
	src = fdapi.decompile(fun)
	if already_done:
		name = prenamed
	else:
		name = src.split("::RTTI")[0].split("&")[-1]
	# if name == "WorldStateComponent":
	# print(src, x.fromAddress)
	if name[-9:] != "Component" or '"class"' not in src:
		continue
	if not already_done:
		fun.setParentNamespace(fpapi.getNamespace(None, name))
		fun.setName("TypeString", SourceType.ANALYSIS)
	refs = program.referenceManager.getReferencesTo(fun.entryPoint)
	for ref in refs:
		ref_fn = fpapi.getFunctionContaining(ref.fromAddress)
		ref_src = fdapi.decompile(ref_fn)
		if (
			"0xf <" not in ref_src
			or "MutexBS" not in ref_src
			or "ComponentIdentifier" not in ref_src
			or "== 0" not in ref_src
		):
			continue
		print("thinker")
		if "-1 <" in ref_src and " & " not in ref_src:
			print("considering", ref_fn.name)
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
			if param.hasStackStorage():
				param.setDataType(
					entity,
					SourceType.ANALYSIS,
				)
		else:
			for double_ref in fpapi.getReferencesTo(ref_fn.entryPoint):
				double_ref_fn = fpapi.getFunctionContaining(double_ref.fromAddress)
				double_ref_src = fdapi.decompile(double_ref_fn)
				if "-1 <" not in double_ref_src or " & " in double_ref_src:
					continue
				print("double reffing saneish")
				if (
					"code **" not in double_ref_src
					and "EntityManger" not in double_ref_src
					and "0x8000" not in double_ref_src
				):
					continue
				print("double reffing done")
				prefix = "FirstEnabled" if "0x8000" in double_ref_src else "First"
				double_ref_fn.setParentNamespace(
					fpapi.getNamespace(None, "EntityManager")
				)
				double_ref_fn.setName(prefix + name, SourceType.ANALYSIS)
				print(name, "double reffed")
				double_ref_fn.setReturnType(
					data_type_manager.getPointer(
						data_type_manager.getDataType("noita.exe/" + name)
					),
					SourceType.ANALYSIS,
				)
				param = double_ref_fn.getParameters()[-1]
				if param.hasStackStorage():
					param.setDataType(
						entity,
						SourceType.ANALYSIS,
					)
