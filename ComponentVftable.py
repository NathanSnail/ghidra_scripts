# TODO write a description for this script
# @author
# @category _Custom
# @keybinding
# @menupath
# @toolbar

import ghidra
from docking.widgets.dialogs import InputDialog
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address

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
		content[name][field] = ty
	return content


def do_vftable(addr, content):
	fpapi = FlatProgramAPI(program)

	fdapi = FlatDecompilerAPI(fpapi)

	ref = [x.getFromAddress() for x in fpapi.getReferencesTo(addr)][0]
	fun = fpapi.getFunctionContaining(ref)
	super_parent = fpapi.getFunctionContaining(
		[x.getFromAddress() for x in fpapi.getReferencesTo(fun.getEntryPoint())][0]
	)
	super_parent_decomp = fdapi.decompile(super_parent)
	size = hex_n(super_parent_decomp.split("operator_new(")[1].split(")")[0])
	print(size)
	parent = fdapi.decompile(fun)
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
		thing["type"] = fields[thing["field"]]
	return things


content = get_types_file()
print(do_vftable(currentAddress, content))
