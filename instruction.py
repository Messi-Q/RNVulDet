import opcodes


class Instruction:
    def __init__(self, offset, pc, opcode, push_data=None):
        self.offset = offset
        self.pc = pc
        assert isinstance(opcode, int)
        self.opcode = opcode
        self.push_data = push_data

    def is_halt_op(self):
        return self.opcode not in opcodes.opcodes or self.opcode in opcodes.halt_op

    def is_push_op(self):
        return self.opcode in opcodes.push_op

    def is_dup_op(self):
        return self.opcode in opcodes.dup_op

    def is_swap_op(self):
        return self.opcode in opcodes.swap_op

    def is_halt_or_unconditional_jump_op(self):
        return self.is_halt_op() or self.opcode == opcodes.JUMP

    def is_arithmetic_op(self):
        return self.opcode in opcodes.arithmetic_op

    def is_mem_read_op(self):
        return self.opcode in opcodes.mem_read_op

    def is_mem_write_op(self):
        return self.opcode in opcodes.mem_write_op

    def is_mem_access_op(self):
        return self.opcode in opcodes.mem_access_op

    def is_mem_rw_op(self):
        return self.opcode in opcodes.mem_rw_op

    def is_call_op(self):
        return self.opcode in opcodes.call_op

    def is_commutative_op(self):
        return self.opcode in opcodes.commutative_op

    def is_taint_op(self):
        return self.opcode in opcodes.taint_op

    def n_pops(self):
        if self.opcode in opcodes.opcodes:
            return opcodes.opcodes[self.opcode][2]
        else:
            return 0

    def n_pushes(self):
        if self.opcode in opcodes.opcodes:
            return opcodes.opcodes[self.opcode][3]
        else:
            return 0

    def get_push_arg(self):
        if self.opcode in opcodes.push_op:
            return opcodes.push_op[self.opcode]
        else:
            return None

    def get_dup_arg(self):
        if self.opcode in opcodes.dup_op:
            return opcodes.dup_op[self.opcode]
        else:
            return None

    def get_swap_arg(self):
        if self.opcode in opcodes.swap_op:
            return opcodes.swap_op[self.opcode]
        else:
            return None

    def get_op_tuple(self, isRead):
        if isRead:
            return opcodes.mem_read_op[self.opcode]
        else:
            return opcodes.mem_write_op[self.opcode]

    def get_mem_start_idx(self, isRead):
        return self.get_op_tuple(isRead)[0]

    def get_mem_len_idx(self, isRead):
        return self.get_op_tuple(isRead)[1]

    @property
    def name(self):
        if self.opcode in opcodes.opcodes:
            return opcodes.opcodes[self.opcode][0]
        elif self.opcode == 0x100:
            return "VALUE"
        elif self.opcode == 0x101:
            return "UNKNOWN"
        elif self.opcode == 0x102:
            return "POSITION"
        else:
            return "GARBAGE %#02x" % self.opcode

    def __eq__(self, _) -> bool:
        raise NotImplementedError

    def __hash__(self) -> int:
        raise NotImplementedError

    def __str__(self):
        if self.push_data is not None:
            return " ".join(["%05x" % self.offset, self.name, hex(self.push_data)])
        else:
            return " ".join(["%05x" % self.offset, self.name])

    to_json = __str__

    def __repr__(self):
        return self.__str__()

    @classmethod
    def get_special_value(cls):
        try:
            return cls.special_value
        except AttributeError:
            cls.special_value = Instruction(0xFFFFE, 0xFFFFE, opcodes.SPECIAL_VALUE)
            return cls.special_value
