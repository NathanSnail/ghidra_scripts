# TODO write a description for this script
# @author NathanSnail
# @category _Custom
# @keybinding
# @menupath
# @toolbar
import ghidra
import ghidra.app.cmd.disassemble.DisassembleCommand
from ghidra.app import decompiler
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.app.script import GhidraState
from ghidra.app.util.cparser.C import CParser
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.data import (ArrayDataType, DataTypeConflictHandler,
                                       DataTypeManager, StringDataType,
                                       StructureDataType)
from ghidra.program.model.lang import DisassemblerContext
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


state = get_state()
addr = get_addr()
program = state.getCurrentProgram()
listing = program.getListing()
dman = program.getDataTypeManager()
fpapi = FlatProgramAPI(program)
fdapi = FlatDecompilerAPI(fpapi)
fman = program.getFunctionManager()
symt = program.getSymbolTable()
cur_fn = fpapi.getFunctionContaining(addr)
for x in fdapi.decompile(cur_fn).split("lua_pushcclosure")[1:]:
    sym = fpapi.getSymbol(x.split(",")[1], fpapi.getNamespace(None, "lua"))
    runCommand(DisassembleCommand(sym.address, None, True))
    fn = fpapi.getFunctionAt(sym.address)
    print(fn.getEntryPoint())
    print(fn)
    if fn.isThunk():
        fn = fn.getThunkedFunction(True)
    inst = listing.getInstructionAt(sym.address)
    if inst.mnemonicString == "JMP":
        fn = fpapi.createFunction(inst.getOperandReferences(0)[0].toAddress, sym.name)

    fn.setName(sym.name, SourceType.ANALYSIS)
    fn.setParentNamespace(fpapi.getNamespace(None, "lua"))
# [
#    (fdapi., fpapi.createFunction(x, y).setParentNamespace(fpapi.getNamespace(None, "lua")))
#    for x, y in [
#        (fpapi.addressFactory.getAddress(fpapi. + x.split(",")[1]), x.split('"')[1])
#    ]
# ]
