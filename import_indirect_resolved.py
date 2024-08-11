# TODO write a description for this script
# @author dextercd
# @category _Custom
# @keybinding
# @menupath
# @toolbar


import csv
import re

from ghidra.program.model.address.Address import *
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing.Listing import *
import ghidra.program.model.symbol as symbol


listing = currentProgram.getListing()
minAddress = currentProgram.getMinAddress()


def remove_generated_comment_parts(comment):
    parts = comment.splitlines(comment)
    parts = [p for p in parts if not re.search('^Calls into .* [0-9]+ times$', p)]

    # Remove leading empty lines
    for part in list(parts):
        if not part.strip():
            parts.pop(0)
        else:
            break

    # Remove following empty lines
    for part in reversed(list(parts)):
        if part.strip() == '':
            parts.pop()
        else:
            break

    return '\n'.join(parts)


def set_comment(addr, comment):
    addr = minAddress.getAddress(hex(addr))
    codeUnit = listing.getCodeUnitAt(addr)
    comment_type = codeUnit.PLATE_COMMENT

    existing_comment = codeUnit.getComment(comment_type)
    if existing_comment:
        cleaned = remove_generated_comment_parts(existing_comment)
        if cleaned:
            comment = cleaned + '\n\n' + comment

    codeUnit.setComment(comment_type, comment)


def annotation_address(to):
    return '{{@address "{:x}"}}'.format(to)


def add_reference(from_, to):
    try:
        source_type = symbol.SourceType.IMPORTED
        ref_type = symbol.RefType.COMPUTED_CALL

        from_addr = minAddress.getAddress(hex(from_))
        to_addr = minAddress.getAddress(hex(to))

        codeUnit = listing.getCodeUnitAt(from_addr)
        codeUnit.addMnemonicReference(to_addr, ref_type, source_type)
    except:
        print("Couldn't add reference from {} to {}".format(from_, to))


with open('/home/nathan/Downloads/indirect_resolved') as resolved_file:
    reader = csv.reader(resolved_file)
    current_addr = None
    for row in reader:
        addr, to, count = row
        addr = int(addr, base=16)
        to = int(to, base=16)

        add_reference(addr, to)

        if current_addr != addr:
            if current_addr is not None:
                set_comment(current_addr, comment)

            current_addr = addr
            comment = ''

        if comment:
            comment += '\n'

        comment += 'Calls into ' + annotation_address(to) + ' ' + str(count) + ' times'

    if current_addr is not None:
        set_comment(current_addr, comment)

