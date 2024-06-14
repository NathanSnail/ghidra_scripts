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


def do_vftable(addr):
	fpapi = FlatProgramAPI(program)

	fdapi = FlatDecompilerAPI(fpapi)

	new_addr = addr.add(14 * 4)
	v = hex(fpapi.getInt(new_addr))
	deref = fpapi.getAddressFactory().getAddress(v)
	decompiled = fdapi.decompile(fpapi.getFunctionAt(deref))
	things = []
	while True:
		found = decompiled.find('"')
		decompiled = decompiled[found + 1 :]
		if found == -1:
			return things
		close = decompiled.find('"')
		if close == -1:
			print("no end found!")
			return things
		data = {}
		data["field"] = decompiled[:close]
		decompiled = decompiled[close + 1 :]
		lines = decompiled.split("}")[0].split("{")[1].split("\n")
		for line in lines:
			print(line)
			if "+" in line:
				add = line.find("+")
				line = line[add + 2 :]
				num = line[:-1]
				if num[0:2] == "0x":
					num = int(num, 16)
				else:
					num = int(num)
				data["offset"]=num
			if "[2]" in line:
				print("[2", line)
				assign = line.find("=")
				line = line[assign + 2 :]
				semi = line.find(";")
				num = line[:semi]
				if num[0:2] == "0x":
					num = int(num, 16)
				else:
					num = int(num)
				data["size"]=num
		things.append(data)

	# TODO Add User Code Here

	print("hi")


print(do_vftable(currentAddress))
