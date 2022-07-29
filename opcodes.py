opcodes = {
    # opcode: (name, push_data_size, n_args, n_rets)
    0x00: ("STOP", 0, 0, 0),
    0x01: ("ADD", 0, 2, 1),
    0x02: ("MUL", 0, 2, 1),
    0x03: ("SUB", 0, 2, 1),
    0x04: ("DIV", 0, 2, 1),
    0x05: ("SDIV", 0, 2, 1),
    0x06: ("MOD", 0, 2, 1),
    0x07: ("SMOD", 0, 2, 1),
    0x08: ("ADDMOD", 0, 3, 1),
    0x09: ("MULMOD", 0, 3, 1),
    0x0A: ("EXP", 0, 2, 1),
    0x0B: ("SIGNEXTEND", 0, 2, 1),
    0x10: ("LT", 0, 2, 1),
    0x11: ("GT", 0, 2, 1),
    0x12: ("SLT", 0, 2, 1),
    0x13: ("SGT", 0, 2, 1),
    0x14: ("EQ", 0, 2, 1),
    0x15: ("ISZERO", 0, 1, 1),
    0x16: ("AND", 0, 2, 1),
    0x17: ("OR", 0, 2, 1),
    0x18: ("XOR", 0, 2, 1),
    0x19: ("NOT", 0, 1, 1),
    0x1A: ("BYTE", 0, 2, 1),
    0x1B: ("SHL", 0, 2, 1),
    0x1C: ("SHR", 0, 2, 1),
    0x1D: ("SAR", 0, 2, 1),
    0x20: ("SHA3", 0, 2, 1),
    0x30: ("ADDRESS", 0, 0, 1),
    0x31: ("BALANCE", 0, 1, 1),
    0x32: ("ORIGIN", 0, 0, 1),
    0x33: ("CALLER", 0, 0, 1),
    0x34: ("CALLVALUE", 0, 0, 1),
    0x35: ("CALLDATALOAD", 0, 1, 1),
    0x36: ("CALLDATASIZE", 0, 0, 1),
    0x37: ("CALLDATACOPY", 0, 3, 0),
    0x38: ("CODESIZE", 0, 0, 1),
    0x39: ("CODECOPY", 0, 3, 0),
    0x3A: ("GASPRICE", 0, 0, 1),
    0x3B: ("EXTCODESIZE", 0, 1, 1),
    0x3C: ("EXTCODECOPY", 0, 4, 0),
    0x3D: ("RETURNDATASIZE", 0, 0, 1),
    0x3E: ("RETURNDATACOPY", 0, 3, 0),
    0x3F: ("EXTCODEHASH", 0, 1, 1),
    0x40: ("BLOCKHASH", 0, 1, 1),
    0x41: ("COINBASE", 0, 0, 1),
    0x42: ("TIMESTAMP", 0, 0, 1),
    0x43: ("NUMBER", 0, 0, 1),
    0x44: ("DIFFICULTY", 0, 0, 1),
    0x45: ("GASLIMIT", 0, 0, 1),
    0x46: ("CHAINID", 0, 0, 1),
    0x47: ("SELFBALANCE", 0, 0, 1),
    0x48: ("BASEFEE", 0, 0, 1),
    0x50: ("POP", 0, 1, 0),
    0x51: ("MLOAD", 0, 1, 1),
    0x52: ("MSTORE", 0, 2, 0),
    0x53: ("MSTORE8", 0, 2, 0),
    0x54: ("SLOAD", 0, 1, 1),
    0x55: ("SSTORE", 0, 2, 0),
    0x56: ("JUMP", 0, 1, 0),
    0x57: ("JUMPI", 0, 2, 0),
    0x58: ("PC", 0, 0, 1),
    0x59: ("MSIZE", 0, 0, 1),
    0x5A: ("GAS", 0, 0, 1),
    0x5B: ("JUMPDEST", 0, 0, 0),
    0x60: ("PUSH1", 1, 0, 1),
    0x61: ("PUSH2", 2, 0, 1),
    0x62: ("PUSH3", 3, 0, 1),
    0x63: ("PUSH4", 4, 0, 1),
    0x64: ("PUSH5", 5, 0, 1),
    0x65: ("PUSH6", 6, 0, 1),
    0x66: ("PUSH7", 7, 0, 1),
    0x67: ("PUSH8", 8, 0, 1),
    0x68: ("PUSH9", 9, 0, 1),
    0x69: ("PUSH10", 10, 0, 1),
    0x6A: ("PUSH11", 11, 0, 1),
    0x6B: ("PUSH12", 12, 0, 1),
    0x6C: ("PUSH13", 13, 0, 1),
    0x6D: ("PUSH14", 14, 0, 1),
    0x6E: ("PUSH15", 15, 0, 1),
    0x6F: ("PUSH16", 16, 0, 1),
    0x70: ("PUSH17", 17, 0, 1),
    0x71: ("PUSH18", 18, 0, 1),
    0x72: ("PUSH19", 19, 0, 1),
    0x73: ("PUSH20", 20, 0, 1),
    0x74: ("PUSH21", 21, 0, 1),
    0x75: ("PUSH22", 22, 0, 1),
    0x76: ("PUSH23", 23, 0, 1),
    0x77: ("PUSH24", 24, 0, 1),
    0x78: ("PUSH25", 25, 0, 1),
    0x79: ("PUSH26", 26, 0, 1),
    0x7A: ("PUSH27", 27, 0, 1),
    0x7B: ("PUSH28", 28, 0, 1),
    0x7C: ("PUSH29", 29, 0, 1),
    0x7D: ("PUSH30", 30, 0, 1),
    0x7E: ("PUSH31", 31, 0, 1),
    0x7F: ("PUSH32", 32, 0, 1),
    0x80: ("DUP1", 0, 1, 2),
    0x81: ("DUP2", 0, 2, 3),
    0x82: ("DUP3", 0, 3, 4),
    0x83: ("DUP4", 0, 4, 5),
    0x84: ("DUP5", 0, 5, 6),
    0x85: ("DUP6", 0, 6, 7),
    0x86: ("DUP7", 0, 7, 8),
    0x87: ("DUP8", 0, 8, 9),
    0x88: ("DUP9", 0, 9, 10),
    0x89: ("DUP10", 0, 10, 11),
    0x8A: ("DUP11", 0, 11, 12),
    0x8B: ("DUP12", 0, 12, 13),
    0x8C: ("DUP13", 0, 13, 14),
    0x8D: ("DUP14", 0, 14, 15),
    0x8E: ("DUP15", 0, 15, 16),
    0x8F: ("DUP16", 0, 16, 17),
    0x90: ("SWAP1", 0, 2, 2),
    0x91: ("SWAP2", 0, 3, 3),
    0x92: ("SWAP3", 0, 4, 4),
    0x93: ("SWAP4", 0, 5, 5),
    0x94: ("SWAP5", 0, 6, 6),
    0x95: ("SWAP6", 0, 7, 7),
    0x96: ("SWAP7", 0, 8, 8),
    0x97: ("SWAP8", 0, 9, 9),
    0x98: ("SWAP9", 0, 10, 10),
    0x99: ("SWAP10", 0, 11, 11),
    0x9A: ("SWAP11", 0, 12, 12),
    0x9B: ("SWAP12", 0, 13, 13),
    0x9C: ("SWAP13", 0, 14, 14),
    0x9D: ("SWAP14", 0, 15, 15),
    0x9E: ("SWAP15", 0, 16, 16),
    0x9F: ("SWAP16", 0, 17, 17),
    0xA0: ("LOG0", 0, 2, 0),
    0xA1: ("LOG1", 0, 3, 0),
    0xA2: ("LOG2", 0, 4, 0),
    0xA3: ("LOG3", 0, 5, 0),
    0xA4: ("LOG4", 0, 6, 0),
    0xF0: ("CREATE", 0, 3, 1),
    0xF1: ("CALL", 0, 7, 1),
    0xF2: ("CALLCODE", 0, 7, 1),
    0xF3: ("RETURN", 0, 2, 0),
    0xF4: ("DELEGATECALL", 0, 6, 1),
    0xF5: ("CREATE2", 0, 4, 1),
    0xFA: ("STATICCALL", 0, 6, 1),
    0xFD: ("REVERT", 0, 2, 0),
    0xFE: ("INVALID", 0, 0, 0),
    0xFF: ("SELFDESTRUCT", 0, 1, 0),

    # SPECIAL:
    0x100: ("MOD_TIME", None, None, None),
    0x101: ("SPECIAL_VALUE", None, None, None),
}

g = globals()
for opcode in opcodes:
    g[opcodes[opcode][0]] = opcode

halt_op = {
    STOP,
    RETURN,
    REVERT,
    INVALID,
    SELFDESTRUCT,
}

jump_op = {
    JUMP,
    JUMPI,
}

arithmetic_op = {
    ADD,
    MUL,
    SUB,
    DIV,
    SDIV,
    MOD,
    SMOD,
    ADDMOD,
    MULMOD,
    EXP,
    SIGNEXTEND,
    LT,
    GT,
    SLT,
    SGT,
    EQ,
    ISZERO,
    AND,
    OR,
    XOR,
    NOT,
    BYTE,
    SHL,
    SHR,
    SAR,
}

push_op = {opcode: opcode - 0x60 + 1 for opcode in range(0x60, 0x80)}

dup_op = {opcode: opcode - 0x80 + 1 for opcode in range(0x80, 0x90)}

swap_op = {opcode: opcode - 0x90 + 1 for opcode in range(0x90, 0xA0)}

mem_read_op = {
    SHA3: (0, 1),
    MLOAD: (0, None, 32),
    CREATE: (1, 2),
    CREATE2: (1, 2),
    RETURN: (0, 1),
    REVERT: (0, 1),
    LOG0: (0, 1),
    LOG1: (0, 1),
    LOG2: (0, 1),
    LOG3: (0, 1),
    LOG4: (0, 1),
    CALL: (3, 4),
    CALLCODE: (3, 4),
    DELEGATECALL: (2, 3),
    STATICCALL: (2, 3),
}

mem_write_op = {
    CALLDATACOPY: (0, 2),
    CODECOPY: (0, 2),
    EXTCODECOPY: (1, 3),
    RETURNDATACOPY: (0, 2),
    MSTORE: (0, None, 32),
    MSTORE8: (0, None, 8),
    CALL: (5, 6),  # n = min(us[6], |o|)
    CALLCODE: (5, 6),  # n = min(us[6], |o|)
    DELEGATECALL: (4, 5),  # n = min(us[5], |o|)
    STATICCALL: (4, 5),  # n = min(us[5], |o|)
}

mem_access_op = mem_read_op.keys() | mem_write_op.keys()
mem_rw_op = mem_read_op.keys() & mem_write_op.keys()

call_op = {
    CALL,
    CALLCODE,
    DELEGATECALL,
    STATICCALL,
}

commutative_op = {
    ADD,
    MUL,
    AND,
    OR,
    XOR,
}

special_op = {
    BLOCKHASH,
    COINBASE,
    DIFFICULTY,
    GASLIMIT,
    MOD_TIME,
}

caller_op = {
    CALLER,
    ORIGIN,
    CALLDATALOAD,
    CALLDATACOPY,
}

time_op = {
    TIMESTAMP,
    NUMBER,
}

mod_op = {
    MOD,
    SMOD,
    ADDMOD,
    MULMOD,
}

taint_op = special_op | caller_op | time_op