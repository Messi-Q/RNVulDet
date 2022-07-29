import copy
import collections

from instruction_instance import InstructionInstance
from disassembler import Disassembler
from instruction import Instruction
from structures import State, Image, MemItem, StoItem
import opcodes

STK, MEM, STO = 0, 1, 2


class Tracker:
    def __init__(
        self, bytecode: bytes, disasm, step: int, todo_keys: list[StoItem] | None = None
    ):
        self.bytecode: bytes = bytecode
        self.disasm: Disassembler = disasm
        if bytecode.startswith(bytes.fromhex("6060604052")):
            mem_head_len = 3
        elif bytecode.startswith(bytes.fromhex("6080604052")):
            mem_head_len = 4
        else:
            raise NotImplementedError(f"Unkown bytecode header: {bytecode[:5].hex()}")
        self.state: State = State(mem_head_len=mem_head_len)
        self.images: collections.defaultdict[int, set[Image]] = collections.defaultdict(
            set
        )
        self.last_call: InstructionInstance | None = None
        self.inst2sn: collections.defaultdict[int, int] = collections.defaultdict(int)
        self.step = step

        if todo_keys is not None:
            self.state.sto.extend(todo_keys)

        InstructionInstance.set_tracker(self)

    def update(self, inst: Instruction) -> InstructionInstance | None:
        inst_instance = InstructionInstance(inst=inst)
        self.state.trace.append(inst_instance)
        self.update_stk(inst_instance)
        self.update_calldata_code_returndata(inst_instance)
        if self.update_mem(inst_instance) is False:
            # means stopping this path
            return None
        self.update_sto(inst_instance)
        self.update_taint(inst_instance)

        if inst.is_call_op():
            inst_instance_stk = copy.copy(inst_instance)
            inst_instance_stk.value = None
            inst_instance_stk.origin = None
            self.state.stk[-1] = inst_instance_stk
            self.last_call = inst_instance

        return inst_instance

    def update_stk(self, inst_instance: InstructionInstance) -> None:
        inst = inst_instance.inst
        stk = self.state.stk
        if inst.is_push_op():
            assert inst.push_data is not None
            inst_instance.value = inst.push_data
            if inst.push_data in self.disasm.jumpdests:
                inst_instance.push_offset = inst.offset
            stk.append(inst_instance)
        elif inst.is_dup_op():
            n = inst.get_dup_arg()
            stk.append(copy.copy(stk[-n]))
        elif inst.is_swap_op():
            n = inst.get_swap_arg()
            stk[-1], stk[-n - 1] = stk[-n - 1], stk[-1]
        else:
            n_pops = inst.n_pops()
            inst_instance.operands[STK] = stk[-1 : -1 - n_pops : -1]
            del stk[len(stk) - n_pops :]

            inst_instance.calculate()
            if inst.opcode == opcodes.CODESIZE:
                inst_instance.value = len(self.bytecode)

            if inst.n_pushes():
                assert inst.n_pushes() == 1
                stk.append(inst_instance)

    def update_calldata_code_returndata(
        self, inst_instance: InstructionInstance
    ) -> None:
        inst = inst_instance.inst
        if inst.opcode == opcodes.CODESIZE:
            inst_instance.value = len(self.bytecode)
        elif inst.opcode == opcodes.CODECOPY:
            if (
                inst_instance.operands[STK][1].get_origin().inst.opcode
                == opcodes.CODESIZE
            ):
                inst_instance.value = 0
            elif (
                inst_instance.operands[STK][1].value is not None
                and inst_instance.operands[STK][2].value is not None
            ):
                code_start = inst_instance.operands[STK][1].value
                code_length = inst_instance.operands[STK][2].value
                assert code_start < code_start + code_length <= len(self.bytecode)
                value = int.from_bytes(
                    self.bytecode[code_start : code_start + code_length], "big"
                )
                inst_instance.value = value
        elif inst.opcode in {opcodes.RETURNDATASIZE, opcodes.RETURNDATACOPY}:
            pass
        elif inst.opcode in (opcodes.CALLDATACOPY, opcodes.CALLDATALOAD):
            if inst.opcode == opcodes.CALLDATALOAD:
                start = inst_instance.operands[STK][0]
            else:
                start = inst_instance.operands[STK][1]
            if start.get_origin().inst.opcode == opcodes.CALLDATASIZE:
                inst_instance.value = 0

    def update_mem(self, inst_instance: InstructionInstance) -> bool:
        inst = inst_instance.inst

        if inst.opcode == opcodes.MSIZE:
            inst_instance.set_origin_value(self.state.fmps[-1])

        if not inst.is_mem_access_op():
            return True

        def returndata(inst_instance: InstructionInstance):
            if inst_instance.inst.opcode != opcodes.RETURNDATACOPY:
                return False
            dst, src, length = inst_instance.operands[STK]
            return (
                dst.value == 0
                and src.value == 0
                and length.get_origin().inst.opcode == opcodes.RETURNDATASIZE
            )

        def revert_panic_or_error(inst_instance: InstructionInstance):
            if inst_instance.inst.opcode != opcodes.MSTORE:
                return False
            if inst_instance.operands[STK][0].value != 0x4:
                return False
            if self.state.mem_head[0] is None:
                return False
            mem0 = self.state.mem_head[0].inst_instance
            if mem0.inst.opcode != opcodes.MSTORE:
                return False
            if mem0.operands[STK][1].value not in [
                (0x4E487B71 << 0xE0),
                (0x08C379A0 << 0xE0),
            ]:
                return False
            return True

        def return_subcall(inst_instance: InstructionInstance):
            if inst_instance.inst.opcode != opcodes.RETURNDATACOPY:
                return False
            if inst_instance.operands[STK][0].value != 0x0:
                return False
            if inst_instance.operands[STK][1].value != 0x0:
                return False
            if inst_instance.operands[STK][2].value != 0x4:
                return False
            return True

        def read_60_data(
            inst_instance: InstructionInstance, start: InstructionInstance
        ):
            if self.state.mem_head_len != 4:
                return False
            if inst_instance.inst.opcode != opcodes.MLOAD:
                return False
            if start.inst.opcode != opcodes.ADD:
                return False
            if start.value != 0x80:
                return False
            a, b = start.operands[STK]
            if a.value != 0x20:
                return False
            if b.value != 0x60:
                return False
            if a.inst.opcode != opcodes.PUSH1:
                return False
            if b.inst.opcode != opcodes.PUSH1:
                return False
            return True

        if inst.is_mem_read_op() and inst.opcode not in {
            opcodes.RETURN,
            opcodes.REVERT,
            opcodes.LOG0,
            opcodes.LOG1,
            opcodes.LOG2,
            opcodes.LOG3,
            opcodes.LOG4,
        }:

            start = inst_instance.get_mem_start(isRead=True).get_origin()
            length = inst_instance.get_mem_length(isRead=True).get_origin()
            if length.value != 0:
                # read mem head
                if inst.opcode == opcodes.MLOAD and start.value in range(
                    0, self.state.mem_head_len * 0x20, 0x20
                ):
                    index = start.value // 0x20
                    if self.state.mem_head[index] is None:
                        self.state.mem_head[index] = MemItem(
                            InstructionInstance.from_value(0),
                            InstructionInstance.from_value(index),
                            InstructionInstance.from_value(32),
                        )
                    inst_instance.operands[MEM] = [self.state.mem_head[index]]
                    inst_instance.set_origin_value(
                        self.state.mem_head[index].inst_instance
                    )
                elif inst.opcode == opcodes.SHA3 and start.value == 0:
                    assert length.value in (0x20, 0x40)
                    if length.value == 0x20:
                        inst_instance.operands[MEM] = self.state.mem_head[:1][:]
                    else:
                        inst_instance.operands[MEM] = self.state.mem_head[:2][:]
                elif read_60_data(inst_instance, start):
                    pass
                else:
                    index = start.find_mem_index()
                    if index != -1:
                        if inst.opcode == opcodes.MLOAD:
                            for temp_item in reversed(self.state.mem[index]):
                                if temp_item.start.id == start.id or (
                                    temp_item.start.value is not None
                                    and start.value is not None
                                    and temp_item.start.value == start.value
                                ):
                                    if temp_item.length.value == 0x20:
                                        inst_instance.operands[MEM] = [temp_item]
                                        inst_instance.set_origin_value(
                                            temp_item.inst_instance
                                        )
                                    break
                                else:
                                    pass
                        else:
                            inst_instance.operands[MEM] = self.state.mem[index][:]

                        if inst.is_call_op():
                            if inst_instance.operands[STK][1].value == 4:
                                pass
                            else:
                                self.state.mem[index] = []

        # mem_read_op may also be mem_write_op
        if inst.is_mem_write_op():
            if inst.opcode in (opcodes.MSTORE, opcodes.MSTORE8):
                origin = inst_instance.operands[STK][1].get_origin()
                inst_instance.set_origin_value(origin)

            start = inst_instance.get_mem_start(isRead=False).get_origin()
            length = inst_instance.get_mem_length(isRead=False).get_origin()
            if length.value != 0:
                # set mem_head and fmps
                if (
                    start.value is not None
                    and start.value < self.state.mem_head_len * 0x20
                ):
                    if (
                        returndata(inst_instance)
                        or revert_panic_or_error(inst_instance)
                        or return_subcall(inst_instance)
                    ):
                        return False
                    assert (
                        inst.opcode == opcodes.MSTORE
                        or inst.opcode == opcodes.CODECOPY
                        and start.value == 0x00
                        and length.value == 0x20
                    )
                    if start.value not in range(
                        0, self.state.mem_head_len * 0x20, 0x20
                    ):
                        return False
                    index = start.value // 0x20
                    self.state.mem_head[index] = MemItem(
                        inst_instance,
                        InstructionInstance.from_value(index),
                        InstructionInstance.from_value(0x20),
                    )
                    if start.value == 0x40:
                        assert inst.opcode == opcodes.MSTORE
                        fmp_origin = inst_instance.operands[STK][1].get_origin()
                        self.state.fmps.append(fmp_origin)
                        self.state.fmpids.append(fmp_origin.id)
                        self.state.mem.append([])
                elif (
                    inst.opcode == opcodes.MSTORE
                    and inst_instance.operands[STK][0].inst.opcode == opcodes.MSIZE
                ):
                    index = len(self.state.fmps) - 1
                    self.state.mem[index] = [MemItem(inst_instance, start, length)]
                else:
                    index = start.find_mem_index()
                    if index != -1:
                        mem_item = MemItem(inst_instance, start, length)

                        newMem = []
                        for temp_item in self.state.mem[index]:
                            if (
                                temp_item.start.id == start.id
                                and temp_item.length.value is not None
                                and length.value is not None
                                and temp_item.length.value <= length.value
                            ):
                                continue
                            else:
                                newMem.append(temp_item)
                        self.state.mem[index] = newMem

                        self.state.mem[index].append(mem_item)
        return True

    def update_sto(self, inst_instance: InstructionInstance) -> None:
        inst = inst_instance.inst
        if inst.opcode == opcodes.SLOAD:
            key = inst_instance.operands[STK][0].get_origin()
            key_poly = key.get_polynomial()
            for sto_item in reversed(self.state.sto):
                if key_poly.eq(sto_item.key.get_polynomial(), silence=True):
                    inst_instance.operands[STO].append(sto_item.inst_instance)
                    sto_origin = sto_item.inst_instance.get_origin()
                    inst_instance.set_origin_value(sto_origin)
                    break
        elif inst.opcode == opcodes.SSTORE:
            inst_instance.set_origin_value(inst_instance.operands[STK][1])
            key = inst_instance.operands[STK][0].get_origin()
            self.state.sto.append(StoItem(key, inst_instance))
        else:
            pass

    def update_taint(self, inst_instance: InstructionInstance) -> None:
        for i in range(3):
            for operand in inst_instance.operands[i]:
                if i == MEM:
                    inst_instance.taint_inst.update(operand.inst_instance.taint_inst)
                    inst_instance.taint_inst.update(operand.start.taint_inst)
                    inst_instance.taint_inst.update(operand.length.taint_inst)
                else:
                    # storage key already in stack
                    inst_instance.taint_inst.update(operand.taint_inst)

        if inst_instance.inst.is_taint_op():
            inst_instance.taint_inst.add(inst_instance.inst.opcode)
        elif (
            inst_instance.inst.opcode in opcodes.mod_op
            and inst_instance.taint_inst & opcodes.time_op
        ):
            inst_instance.taint_inst.add(opcodes.MOD_TIME)

    def update_images(self, start_offset: int) -> None:
        image = Image(self.state.stk)
        if image in self.images[start_offset]:
            return False
        else:
            self.images[start_offset].add(image)
            return True
