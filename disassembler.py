import opcodes
import instruction


class Disassembler:
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.instructions: dict[int, instruction.Instruction] = {}
        self.instructions_list: list[instruction.Instruction] = []
        self.jumpdests: set[int] | None = None
        self.invalid_jumpdests: set[int] | None = None
        self.opcodes: set[int] = set()

    def disassemble(self):
        offset, pc, bytecode = 0, 0, self.bytecode
        end = len(bytecode)
        dead = False

        while offset < end:
            opcode = bytecode[offset]

            if opcode == opcodes.JUMPDEST:
                dead = False

            if opcode in opcodes.opcodes:
                push_data_size = opcodes.opcodes[opcode][1]
            else:
                push_data_size = 0

            push_data = self.get_push_data(offset + 1, push_data_size, end)

            inst = instruction.Instruction(offset, pc, opcode, push_data)
            self.add_instruction(inst, dead=dead)

            if inst.is_halt_or_unconditional_jump_op():
                dead = True

            offset += 1 + push_data_size
            pc += 1

        if not dead:
            # append STOP instruction
            inst = instruction.Instruction(offset, pc, opcodes.STOP, None)
            self.add_instruction(inst, dead=dead)

        self.jumpdests = {
            offset
            for offset, inst in self.instructions.items()
            if inst.opcode == opcodes.JUMPDEST
        }
        self.invalid_jumpdests = {0, 2, 7} - self.jumpdests

    def add_instruction(self, inst: instruction.Instruction, dead: bool):
        self.instructions[inst.offset] = inst
        self.instructions_list.append(inst)
        if not dead:
            self.opcodes.add(inst.opcode)

    def at(self, pc=None, offset=None) -> instruction.Instruction:
        if pc is not None:
            return self.instructions_list[pc]
        else:
            return self.instructions[offset]

    def get_push_data(self, offset: int, push_data_size, end):
        if not push_data_size:
            return None
        data_end = offset + push_data_size
        if data_end <= end:
            data_bytes = self.bytecode[offset:data_end]
        else:
            # append 0s
            data_bytes = self.bytecode[offset:end] + bytes(data_end - end)
        push_data = int.from_bytes(data_bytes, "big")
        return push_data
