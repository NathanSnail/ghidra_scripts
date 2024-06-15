# TODO write a description for this script
# @author
# @category _Custom
# @keybinding
# @menupath
# @toolbar

import ghidra
from docking.widgets.dialogs import InputDialog
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
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

state = getState()
program = state.getCurrentProgram()


def hex_n(n):
	if n[0:2] == "0x":
		num = int(n, 16)
	else:
		num = int(n)
	return num


type_defs = {
	"int32": "int",
	"uint32": "uint",
	"uint32_t": "uint",
	"unsigned int": "uint",
	"int64": "longlong",
	"uint64": "ulonglong",
	"std::string": "StdString",
	"EntityID": "int",
	"int16": "short",
	"uint16": "ushort",
}


def get_types_file():
	file = askFile("Component Docs", "Approve").getAbsolutePath()
	content = open(file, "r").read()
	lines = content.replace("\r", "").split("\n")
	name = ""
	content = {}
	for line in lines:
		if line == "":
			continue
		if line[0] != " ":
			name = line
			content[name] = {}
			continue
		if line[1] == "-":
			continue
		if line[27] != " ":
			print("error missing seperator", line)
			line = line[:27] + " " + line[28:]
		ty = "".join([x for x in line[:27].split(" ") if x != ""])
		field = line[28:].split(" ")[0]
		if ty in type_defs.keys():
			ty = type_defs[ty]
		content[name][field] = (ty, line[125:].replace('"', ""))
	return content


def do_vftable(addr, content):
	fpapi = FlatProgramAPI(program)

	fdapi = FlatDecompilerAPI(fpapi)

	ref = [x.getFromAddress() for x in fpapi.getReferencesTo(addr)][0]
	fun = fpapi.getFunctionContaining(ref)
	super_parents = [
		fpapi.getFunctionContaining(x.getFromAddress())
		for x in fpapi.getReferencesTo(fun.getEntryPoint())
	]
	size = None
	for super_parent in super_parents:
		super_parent_decomp = fdapi.decompile(super_parent)
		if "operator_new(" not in super_parent_decomp:
			continue
		if size is not None:
			continue
		size = hex_n(super_parent_decomp.split("operator_new(")[1].split(")")[0])

	parent = fdapi.decompile(fun)
	if size is None:
		size = hex_n(parent.split("operator_new(")[1].split(")")[0])
	print(size)
	name = parent.split('"')[1]
	print(name)
	new_addr = addr.add(14 * 4)
	v = hex(fpapi.getInt(new_addr))
	deref = fpapi.getAddressFactory().getAddress(v)
	decompiled = fdapi.decompile(fpapi.getFunctionAt(deref))
	things = []
	while True:
		data = {}
		found = decompiled.find('"')
		decompiled = decompiled[found + 1 :]
		if found == -1:
			break
		close = decompiled.find('"')
		if close == -1:
			print("no end found!")
			break
		data["field"] = str(decompiled[:close])
		decompiled = decompiled[close + 1 :]
		lines = decompiled.split("}")[0].split("{")[1].split("\n")
		# } stupid vim
		for line in lines:
			if "+" in line:
				add = line.find("+")
				line = line[add + 2 :]
				num = line[:-1]
				num = hex_n(num)
				data["offset"] = num
			if "[2]" in line:
				assign = line.find("=")
				line = line[assign + 2 :]
				semi = line.find(";")
				num = line[:semi]
				num = hex_n(num)
				data["size"] = num
		things.append(data)

	fields = content[name]
	for thing in things:
		thing["type"] = fields[thing["field"]][0]
		thing["comment"] = fields[thing["field"]][1]
	return things, name, size


def construct_structs(defs, name, size):
	data_type_manager = currentProgram.getDataTypeManager()
	struct = StructureDataType(name, size)
	struct.replaceAtOffset(
		0,
		data_type_manager.getDataType("noita.exe/ComponentMysteryData"),
		0x48,
		"inherited_fields",
		"",
	)
	defs.sort(lambda x, y: x["offset"] > y["offset"])
	for thing in defs:
		ty = data_type_manager.getDataType("/" + thing["type"])
		if ty is None:
			ty = data_type_manager.getDataType("noita.exe/" + thing["type"])
		if ty is None:
			ty = ArrayDataType(
				data_type_manager.getDataType("/undefined1"), thing["size"], 1
			)
		print(thing["offset"], thing["field"])
		struct.replaceAtOffset(
			thing["offset"], ty, thing["size"], thing["field"], thing["comment"]
		)
	data_type_manager.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)

	# ty = data_type_manager.getDataType("/" + )
	# parser = CParser(data_type_manager)
	# parsed_datatype = parser.parse(struct_str)
	# data_type_manager.addDataType(
	# 	parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER
	# )


content = get_types_file()
things, name, size = do_vftable(currentAddress, content)
construct_structs(things, name, size)
