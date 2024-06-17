# TODO write a description for this script
# @author
# @category _Custom
# @keybinding
# @menupath
# @toolbar

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
	content = {
		"ParticleEmitterComponent": {
			"custom_style": "PARTICLE_EMITTER_CUSTOM_STYLE::Enum",
			"m_cached_image_animation": "ParticleEmitter_Animation*",
		},
		"ExplosionComponent": {"trigger": "EXPLOSION_TRIGGER_TYPE::Enum"},
		"InventoryComponent": {"update_listener": "InvenentoryUpdateListener*"},
		"PathFindingComponent": {
			"job_result_receiver": "MSG_QUEUE_PATH_FINDING_RESULT"
		},
	}
	for line in lines:
		if line == "":
			continue
		if line[0] != " ":
			name = line
			if name not in content.keys():
				content[name] = {}
			continue
		if line[1] == "-":
			continue
		if line[27] != " ":
			print("error missing seperator", line)
			continue
		ty = "".join([x for x in line[:27].split(" ") if x != ""])
		field = line[28:].split(" ")[0]
		if ty in type_defs.keys():
			ty = type_defs[ty]
		content[name][field] = (ty, line[125:].replace('"', ""))
	return content


def do_vftable(addr, content, name):

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
	derived_size = False
	if size is None:
		if "operator_new(" in parent:
			size = hex_n(parent.split("operator_new(")[1].split(")")[0])
		else:
			derived_size = True
			size = 0x48
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
				if derived_size:
					size = max(size, num)
		things.append(data)

	fields = content[name]
	for thing in things:
		thing["type"] = fields[thing["field"]][0]
		thing["comment"] = fields[thing["field"]][1]
	return things, size


def construct_structs(defs, name, size):
	data_type_manager = currentProgram.getDataTypeManager()
	if data_type_manager.getDataType("noita.exe/" + name) is not None:
		return
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


def get_all():
	table = program.getSymbolTable()
	addrs = []
	for i in table.getClassNamespaces():
		search = "Component"
		n = i.name
		if n[-len(search) :] != search or n == search:
			continue
		for s in table.getChildren(i.symbol):
			if s.name != "vftable":
				continue
			addrs.append((s.address, n))
	return addrs


content = get_types_file()


def do(pair):
	try:
		things, size = do_vftable(pair[0], content, pair[1])
		construct_structs(things, pair[1], size)
	except Exception as e:
		print(e)
		print(type(e))
		print(pair[1], "failed")
		pass


# do_vftable(currentAddress, content, "AIAttackComponent")
[do(x) for x in get_all()]
