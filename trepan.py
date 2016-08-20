import struct, sys
# should contain an array called 'words' of all the 32-bit words that make up
# the initial memory of the skullcode VM, extracted from the page source
from source import *

BIT_ADDRESS_MODE = 0x8000
BIT_INDIRECT_MODE = 0x0800

# these two functions decode the addressing modes of the source and destination
# operands of a given instruction word; second entry of tuple is extra size
# consumed by literal source operands
def sourceDecode(addr):
    instr = words[addr]
    slot = instr >> 24
    size = (instr >> 8) & 0x07
    base = (instr >> 12) & 0x07
    if instr & BIT_ADDRESS_MODE:
        if size == 0:
            return ("lit", 0, size, slot)
        elif size == 1:
            return ("lit", 1, size, words[addr+1] & 0xFFFF)
        elif size == 2:
            if slot != 0:
                return ("reg", 0, slot)
            else:
                return ("lit", 1, size, words[addr+1])
        elif size == 7 or size ==4:
            return ("lit", 4, size, words[addr+1] | words[addr+2] << 32 |
                    words[addr+3] << 64 | words[addr+4] << 96)
        elif size == 3:
            return ("lit", 2, size, words[addr+1] | words[addr+2] << 32)
        elif size == 5:
            return ("lit", 1, size, floatunpack(words[addr+1], 1))
        elif size == 6:
            aligned = (addr + 1) + ((addr + 1) & 1)
            return ("lit", ((addr + 1) & 1) + 2, size,
                    floatunpack(words[aligned] | words[aligned] << 32, 2))
    if instr & BIT_INDIRECT_MODE or base == 0:
        return ("stack", 0, size, slot)
    else:
        return ("indir", 0, size, slot, base)

def destDecode(addr):
    instr = words[addr]
    slot = (instr >> 16) & 0xff
    size = (instr >> 8) & 0x07
    base = (instr >> 12) & 0x07
    if instr & BIT_INDIRECT_MODE:
        if base == 0:
            return ("reg", 0, slot)
        else:
            return ("indir", 0, size, slot, base)
    else:
        return ("stack", 0, size, slot)

# pretty-prints the output of the operand decoders
def formatAddr(addr):
    if addr[0] == "lit":
        if addr[2] == 0: return "byte 0x" + format(addr[3], 'x')
        if addr[2] == 1: return "short 0x" + format(addr[3], 'x')
        if addr[2] == 2: return "0x" + format(addr[3], 'x')
        if addr[2] == 3: return "long 0x" + format(addr[3], 'x')
        if addr[2] == 4 or addr[2] == 7: return "huge 0x" + format(addr[3], 'x')
        if addr[2] == 5: return "float " + format(addr[3], 'g')
        if addr[2] == 6: return "double " + format(addr[3], 'g')
    if addr[0] == "reg": return registers.get(addr[2], "???")
    if addr[0] == "stack": return sizenames[addr[2]] + "mem[" + str(addr[3]) + "]"
    if addr[0] == "indir":
        return (sizenames[addr[2]] + "[mem[" + str(addr[3]) + "]" + ("+" + registers.get(addr[4], "???") if addr[4] != 7 else "") + "]")

# pretty-prints one whole instruction
def formatInstr(addr):
    op = words[addr] & 0xff
    if op in opcodeTypes["none"]: return opcodes[op]
    if op in opcodeTypes["src"]: return opcodes[op] + " " + formatAddr(sourceDecode(addr))
    if op in opcodeTypes["dest"]: return opcodes[op] + " " + formatAddr(destDecode(addr))
    if op in opcodeTypes["shift"] and (words[addr] & 0x8000):
        return opcodes[op] + " " + formatAddr(destDecode(addr)) + ", " + format(words[addr] >> 24)
    if op in opcodeTypes["both"]:
        return opcodes[op] + " " + formatAddr(destDecode(addr)) + ", " + formatAddr(sourceDecode(addr))
    if op == 0x0b:
        jmpMode = (words[addr] >> 18) & 0x3f
        flag = jmpFlags[jmpMode] if jmpMode in jmpFlags else "??"
        return "j" + flag + " " + formatAddr(sourceDecode(addr))
    if op == 0x1f:
        return "call " + formatAddr(sourceDecode(addr)) + ", " + format((words[addr] >> 14) & 0x3fc)

# given an initial address, disassembles instructions up until it encounters a
# break in control flow, also returns all addresses possibly jumped to in the block
def formatBlock(addr):
    i = addr
    listing = ""
    labels = []
    while i < len(words):
        op = words[i] & 0xff
        if not op in opcodes:
            break
        else:
            src = sourceDecode(i)
        listing += format(i * 4, '04x') + " " + formatInstr(i) + "\n"
        if op in [0x0b, 0x1f] and src[0] == "lit":
            labels.append(src[3] >> 2)
        if op in [0x00, 0x01, 0x20]:
            break
        if op == 0x0b and (words[i] >> 18) & 0x3f == 0:
            break
        i += src[1] + 1
    labels = [l for l in labels if not addr <= l <= i]
    return (labels, listing)

# recursively runs formatBlock on all source accessible form the initial address
def formatBlocks(addr):
    blocks = {addr}
    listings = {}
    while blocks - set(listings.keys()):
        block = (blocks - set(listings.keys())).pop()
        (labels, listing) = formatBlock(block)
        blocks |= set(labels)
        listings[block] = listing
    return listings

# sticks all the disassembled blocks together and writes them to a file
def writeListings(addr, file = sys.stdout):
    listings = formatBlocks(addr)
    blocks = sorted(listings.keys())
    strings = [listings[b] for b in blocks]
    file.write("\n\n".join(strings))

# writes every valid instruction in the source when you can't find the next damn
# stage of the puzzle
def dumpAll(file = sys.stdout):
    i = 0
    while i < len(words):
        instr = words[i]
        op = words[i] & 0xff
        if op in opcodes:
            file.write(format(i * 4, '04x') + " " + formatInstr(i) + "\n")
            i += sourceDecode(i)[1]
            i += 1
        else:
            file.write("\n\n")
            i += 1


def floatpack(x, size):
    if size == 1:
        return struct.unpack("<I", struct.pack("<f", x))
    elif size == 2:
        return struct.unpack("<L", struct.pack("<d", x))

def floatunpack(x, size):
    if size == 1:
        return struct.unpack("<f", struct.pack("<I", x))
    elif size == 2:
        return struct.unpack("<d", struct.pack("<d", x))

# register names (essentially memory segment addresses in the VM)
registers = {
    0x01 : "rHeap",
    0x02 : "rParam",
    0x03 : "rText",
    0x04 : "rEntity",
    0x05 : "rCode",
    0x06 : "rCall",
    0x07 : "cmp",
    0x09 : "body",
    0x0a : "spine",
    0x0b : "free",
    0x0c : "seed",
    0x0d : "rSig",
    0x0e : "rVirt",
    0x0f : "iOff"
}

# opcode names
opcodes = {
    0x00 : "halt",
    0x01 : "err",
    0x02 : "wait",
    0x03 : "finger",
    0x04 : "clrfng",
    0x05 : "stolck",
    0x06 : "set16",
    0x07 : "setlck",
    0x08 : "setrng",
    0x09 : "mov",
    0x0a : "cmp",
    0x0b : "jmp",
    0x0d : "add",
    0x0e : "sub",
    0x0f : "not",
    0x10 : "xor",
    0x11 : "and",
    0x12 : "or",
    0x13 : "shl",
    0x14 : "shrx",
    0x15 : "shr",
    0x16 : "rotl",
    0x17 : "rotr",
    0x18 : "sgnext",
    0x19 : "neg",
    0x1a : "mul",
    0x1b : "div",
    0x1c : "mod",
    0x1d : "udiv",
    0x1e : "umod",
    0x1f : "call",
    0x20 : "ret",
    0x23 : "conv",
    0x28 : "log",
    0x29 : "time",
    0x2a : "since"
}

# what operands each opcode uses
opcodeTypes = {
    "none"  : [0x00, 0x04, 0x07, 0x20, 0x28],
    "src"   : [0x01, 0x02, 0x08, 0x23],
    "dest"  : [0x05, 0x06, 0x29, 0x2a],
    "both"  : [0x03, 0x09, 0x0a, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e],
    "shift" : [0x13, 0x14, 0x15, 0x16, 0x17]
}

# conditional jump modes
jmpFlags = {
    0  : "mp",
    1  : "eq",
    2  : "l",   # signed comparison
    3  : "le",
    4  : "g",
    5  : "ge",
    6  : "ne",
    7  : "b",   # unsigned
    8  : "be",
    9  : "a",
    10 : "ae"
}

# operand sizes/types
sizenames = {
    0 : "byte ",    # 8-bit
    1 : "short ",   # 16-bit
    2 : "",         # 32-bit
    3 : "long ",    # 64-bit
    4 : "huge ",    # 128-bit
    5 : "float ",
    6 : "double ",
    7 : "huge "
}
