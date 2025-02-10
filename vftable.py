# TODO write a description for this script
# @author NathanSnail
# @category _Custom
# @keybinding
# @menupath
# @toolbar

import ghidra
from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.app.script import GhidraState
from ghidra.app.util.cparser.C import CParser
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address
from ghidra.program.model.data import (ArrayDataType, CategoryPath, DataType,
                                       DataTypeConflictHandler,
                                       DataTypeManager,
                                       FunctionDefinitionDataType,
                                       PointerDataType, PointerType,
                                       StringDataType, StructureDataType)
from ghidra.program.model.listing import Data, FunctionSignature, Program
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import TaskMonitor


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
decomp_i = DecompInterface()
decomp_i.openProgram(program)

sym = symt.getPrimarySymbol(addr)
path = ""
namespace = sym.getParentNamespace()
while namespace and namespace.getParentNamespace() and not namespace.isGlobal():
    path += "/" + namespace.getName()
    namespace = namespace.getParentNamespace()

def tinkerWithType(t):
    # type: (DataType) -> DataType
    name = t.name
    if "WorldStateComponent" in name:
        return dman.getPointer(dman.getDataType("noita.exe/Component"))
    if "ConfigGun" in name:
        return dman.getPointer(dman.getDataType("noita.exe/ConfigBase"))
    return t

dirty = True

data = listing.getDataAt(addr)
data_type = data.getDataType()
print(data_type, data_type.length)
fields = []
cat = CategoryPath(path + "/vftable")
for i in range(data_type.length // 4):
    item = data.getComponentAt(i * 4)
    function_address = item.getValue()
    function = fpapi.getFunctionAt(function_address)
    prototype = decomp_i.decompileFunction(function, 30, None).getHighFunction().getFunctionPrototype()
    ret_t = tinkerWithType(prototype.returnType)
    sig = function.getSignature()
    fn_t = FunctionDefinitionDataType(sig)
    for arg in fn_t.arguments:
        arg.setDataType(tinkerWithType(arg.dataType))
    fn_t.setReturnType(ret_t)
    fn_t.setCategoryPath(cat)
    if dirty:
        dt = dman.addDataType(fn_t, DataTypeConflictHandler.REPLACE_HANDLER)
        fields.append((dt, function.getName()))

print(fields)

if dirty:
    struct = StructureDataType("vftable_struct", len(fields) * 4)
    struct.setCategoryPath(cat)
    for k, f in enumerate(fields):
        print(f)
        struct.replaceAtOffset(k * 4, PointerDataType(f[0]), 4, f[1], "")
    dt = dman.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
