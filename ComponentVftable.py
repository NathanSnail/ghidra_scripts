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


def do_vftable(addr):
	fpapi = FlatProgramAPI(program)

	fdapi = FlatDecompilerAPI(fpapi)

	ref = [x.getFromAddress() for x in fpapi.getReferencesTo(addr)][0]
	fun = fpapi.getFunctionContaining(ref)
	super_parent = fpapi.getFunctionContaining([x.getFromAddress() for x in fpapi.getReferencesTo(fun.getEntryPoint())][0])
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
	data = {}
	while True:
		found = decompiled.find('"')
		decompiled = decompiled[found + 1 :]
		if found == -1:
			break
		close = decompiled.find('"')
		if close == -1:
			print("no end found!")
			break
		data["field"] = decompiled[:close]
		decompiled = decompiled[close + 1 :]
		lines = decompiled.split("}")[0].split("{")[1].split("\n")
		for line in lines:
			if "+" in line:
				add = line.find("+")
				line = line[add + 2 :]
				num = line[:-1]
				num = hex_n(num)
				data["offset"]=num
			if "[2]" in line:
				assign = line.find("=")
				line = line[assign + 2 :]
				semi = line.find(";")
				num = line[:semi]
				num = hex_n(num)
				data["size"]=num
		things.append(data)

	# TODO Add User Code Here

	return data


print(do_vftable(currentAddress))
