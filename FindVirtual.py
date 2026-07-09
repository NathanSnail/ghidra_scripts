# TODO write a description for this script
# @author NathanSnail
# @category _Custom
# @keybinding
# @menupath
# @toolbar

from ghidra.program.model.symbol import RefType

def is_indirect_call(instr):
    flow_type = instr.getFlowType()
    if not flow_type.isCall():
        return False
    return flow_type.isComputed()


def resolves_to_known_external(instr):
    for ref in instr.getReferencesFrom():
        to_addr = ref.getToAddress()

        sym = getSymbolAt(to_addr)
        if sym is not None and sym.isExternal():
            return True

        # pointers to external data are also boring
        data = getDataAt(to_addr)
        if data is not None:
            for dref in data.getReferencesFrom():
                dsym = getSymbolAt(dref.getToAddress())
                if dsym is not None and dsym.isExternal():
                    return True

    return False


def run():
    listing = currentProgram.getListing()
    instrs = listing.getInstructions(True)

    out_path = askFile("Save indirect call addresses to", "Save").getAbsolutePath()
    count = 0
    skipped = 0
    with open(out_path, "w") as f:
        for instr in instrs:
            if not is_indirect_call(instr):
                continue
            if resolves_to_known_external(instr):
                skipped += 1
                continue
            f.write("{}\n".format(instr.getAddress()))
            count += 1
    println("Wrote {} address(es), excluded {} DLL-resolved call(s), to {}".format(
        count, skipped, out_path))


run()
