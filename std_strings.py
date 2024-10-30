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
from ghidra.program.model.lang import OperandType
from ghidra.program.model.listing import Program
from ghidra.program.model.symbol import SourceType


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


def uint8(integral):
	return integral if integral >= 0 else integral + 256


def as_int(ilist):
	if ilist:
		return uint8(ilist[0]) + 256 * as_int(ilist[1:])
	return 0


def map(li, fn):
	return [fn(x) for x in li]


state = get_state()
addr = get_addr()
program = state.getCurrentProgram()
listing = program.getListing()
data_type_manager = program.getDataTypeManager()
fpapi = FlatProgramAPI(program)
fdapi = FlatDecompilerAPI(fpapi)
ss_t = data_type_manager.getDataType("noita.exe/StdString")
str_t = data_type_manager.getDataType("/string")


def proccess(addr):
	fn_addr = fpapi.getBytes(addr, 4)
	fn_addr = map(fn_addr, uint8)
	addr_hex = hex(as_int(fn_addr))
	addr_real = fpapi.getAddressFactory().getAddress(addr_hex)
	fn = fpapi.createFunction(addr_real, "Init_" + addr_hex[2:])
	fpapi.getFunctionAt(addr_real).setName("Init_" + addr_hex[2:], SourceType.ANALYSIS)
	print(fn.entryPoint)
	instrs = [x for x in listing.getInstructions(fn.getBody(), True)]
	if instrs[0].mnemonicString != "PUSH":
		return
	if instrs[1].mnemonicString != "PUSH":
		return
	refs = instrs[1].getOperandReferences(0)
	if not refs:
		return
	straddr = refs[0].toAddress
	if instrs[2].mnemonicString != "MOV":
		return
	if instrs[2].getOperandType(0) != OperandType.REGISTER:
		return
	dat_addr = instrs[2].getOperandReferences(1)[0].toAddress
	if instrs[3].mnemonicString != "CALL":
		return
	if (
		fpapi.getFunctionAt(instrs[3].getOperandReferences(0)[0].toAddress).name
		!= "FromCharLen"
	):
		return
	addr_data = fpapi.getDataAt(straddr)
	if addr_data is None:
		fpapi.createData(straddr, str_t)
	else:
		addr_dt = addr_data.getDataType()
		if str(addr_dt.name) != "string":
			print(str(addr_dt.name), addr_dt.length)
			fpapi.clearListing(dat_addr, dat_addr.add(addr_dt.getLength() - 1))
			fpapi.createData(straddr, str_t)
	str_txt = "ss_" + fpapi.getDataAt(straddr).value
	replaced_name = str_txt.replace(" ", "_")
	fpapi.createLabel(dat_addr, replaced_name, True)
	fpapi.clearListing(dat_addr, dat_addr.add(ss_t.getLength() - 1))
	fpapi.createData(dat_addr, ss_t)
	fn.setName("Init_" + replaced_name, SourceType.ANALYSIS)
	for ref in fpapi.getReferencesTo(dat_addr):
		ref_fn = fpapi.getFunctionContaining(ref.fromAddress)
		ref_instrs = [x for x in listing.getInstructions(ref_fn.getBody(), True)]
		if len(ref_instrs) <= 4:
			continue
		if ref_instrs[3].mnemonicString != "CMP":
			continue
		if str(ref_instrs[3].getDefaultOperandRepresentation(1)) != "0x10":
			continue
		ref_fn.setName("Free_" + replaced_name, SourceType.ANALYSIS)


# proccess(addr)
# exit()

while True:
	if not [x for x in fpapi.getBytes(addr, 4) if x != 0]:
		break
	proccess(addr)
	addr = addr.add(4)
