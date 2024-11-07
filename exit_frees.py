# TODO write a description for this script
# @author NathanSnail
# @category _Custom
# @keybinding
# @menupath
# @toolbar

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI
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


state = get_state()
addr = get_addr()
program = state.getCurrentProgram()
listing = program.getListing()
data_type_manager = program.getDataTypeManager()
fpapi = FlatProgramAPI(program)
fdapi = FlatDecompilerAPI(fpapi)

fn = fpapi.getFunction("MutexLockingOnExitFreeingNonsense")
for ref in fpapi.getReferencesTo(fn.entryPoint):
	rfn = fpapi.getFunctionContaining(ref.fromAddress)
	insts = [x for x in listing.getInstructions(rfn.getBody(), True)]
	for k, inst in enumerate(insts):
		if inst.address == ref.fromAddress:
			print(inst.address)
			for idx in range(k, -1, -1):
				if insts[idx].mnemonicString == "PUSH":
					print("ham")
					freer = insts[idx].getDefaultOperandRepresentation(0)
					print(freer, type(freer))
					fn = fpapi.getFunctionContaining(fpapi.getAddressFactory().getAddress(freer))
					if fn is not None:
						if fn.name[:3] == "FUN":
							fn.setName("Free_" + freer, SourceType.ANALYSIS)
						print(fn)
					break
