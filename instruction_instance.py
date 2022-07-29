from __future__ import annotations
import logging
from typing import TYPE_CHECKING

import instruction
import opcodes
from structures import MemItem, Polynomial

if TYPE_CHECKING:
    from tracker import Tracker

STK, MEM, STO = 0, 1, 2


class InstructionInstance:
    tracker: Tracker = None
    constants: dict[int, InstructionInstance] = {}

    def __init__(self, inst: instruction.Instruction):
        self.inst: instruction.Instruction = inst
        tracker = self.__class__.tracker
        self.sn = tracker.inst2sn[inst.offset]
        tracker.inst2sn[inst.offset] += 1
        self.id: int = (self.sn << 24) + (tracker.step << 20) + self.inst.offset
        self.operands: list[list[InstructionInstance] | list[MemItem]] = [[], [], []]
        self.value: int | None = None
        self.origin: InstructionInstance | None = None
        self.push_offset: int | None = None
        self.polynomial: Polynomial | None = None
        self.taint_inst: set[int] = set()

    @classmethod
    def from_value(cls, value: int) -> InstructionInstance:
        if value in cls.constants:
            return cls.constants[value]
        inst = instruction.Instruction.get_special_value()
        inst_instance = cls(inst)
        inst_instance.value = value
        cls.constants[value] = inst_instance
        return inst_instance

    @classmethod
    def set_tracker(cls, tracker_: Tracker) -> None:
        cls.tracker = tracker_

    @property
    def hex_value(self) -> str:
        try:
            return hex(self.value)
        except TypeError:
            return "None"

    def __repr__(self):
        return self.inst.__repr__() + " " + self.hex_value

    def __eq__(self, _) -> bool:
        raise NotImplementedError

    def __hash__(self) -> int:
        raise NotImplementedError

    def get_origin(self) -> InstructionInstance:
        if self.origin is None:
            return self
        else:
            return self.origin

    def find_mem_index_dfs(self) -> int:
        if self.get_origin() is not self:
            return self.get_origin().find_mem_index_dfs()
        if self.id in self.tracker.state.fmpids:
            return self.tracker.state.fmpids.index(self.id)
        if self.inst.opcode in (opcodes.ADD, opcodes.AND):
            index = self.operands[STK][0].find_mem_index_dfs()
            if index != -1:
                return index
            return self.operands[STK][1].find_mem_index_dfs()
        if (
            self.inst.opcode == opcodes.SUB
            and self.operands[STK][1].value == 0x20
            and self.operands[STK][0].get_origin().id in self.tracker.state.fmpids
        ):
            fmpids = self.tracker.state.fmpids
            index = fmpids.index(self.operands[STK][0].get_origin().id) - 1
            assert index >= 0
            cur_fmp = self.tracker.state.fmps[index]
            next_fmp = self.tracker.state.fmps[index + 1]
            assert next_fmp.inst.opcode == opcodes.ADD
            a, b = next_fmp.operands[STK]
            a, b = a.get_origin(), b.get_origin()
            assert (
                a.value == 0x20
                and b.id == cur_fmp.id
                or b.value == 0x20
                and a.id == cur_fmp.id
            )
            return index
        if self.inst.opcode == opcodes.SUB:
            x0, x1 = self.operands[STK]
            if x0.inst.opcode == opcodes.ADD and x1.inst.opcode == opcodes.AND:
                x00, x01 = x0.operands[STK]
                x10, x11 = x1.operands[STK]
                if x10.value == 0x1F and x00.id == x11.id:
                    return x01.find_mem_index_dfs()
        if self.inst.opcode == opcodes.MLOAD:
            return self.operands[STK][0].find_mem_index_dfs()
        return -1

    def find_mem_index(self) -> int:
        index = self.find_mem_index_dfs()
        if index == -1:
            logging.warning("mem_index not found!")
        return index

    def use_special_inst(self) -> bool:
        return bool(opcodes.special_op & self.taint_inst)

    def get_mem_start(self, isRead) -> InstructionInstance:
        index = self.inst.get_mem_start_idx(isRead)
        mem_start = self.operands[STK][index].get_origin()
        return mem_start

    def get_mem_length(self, isRead) -> InstructionInstance:
        if self.inst.opcode in (opcodes.MLOAD, opcodes.MSTORE):
            return InstructionInstance.from_value(32)
        if self.inst.opcode == opcodes.MSTORE8:
            return InstructionInstance.from_value(8)
        index = self.inst.get_mem_len_idx(isRead)
        return self.operands[STK][index]

    def get_polynomial(self) -> Polynomial:
        if self.polynomial is not None:
            return self.polynomial

        if self.value is not None:
            self.polynomial = Polynomial(cst=self.value)
            return self.polynomial

        origin = self.get_origin()

        if origin.polynomial is not None:
            self.polynomial = origin.polynomial
            return self.polynomial

        opcode = origin.inst.opcode
        if opcode not in {opcodes.ADD, opcodes.SUB}:
            if opcode == opcodes.SHA3:
                n = opcode
                for mem_item in origin.operands[MEM]:
                    operand = mem_item.inst_instance
                    n = n << 257
                    if operand.inst.is_push_op():
                        n += 2**256 + operand.inst.push_data
                    else:
                        n += operand.inst.opcode
                terms = [n]
            else:
                terms = [opcode]
            origin.polynomial = Polynomial(terms=terms)
            self.polynomial = origin.polynomial
            return self.polynomial

        a_poly = origin.operands[STK][0].get_polynomial()
        b_poly = origin.operands[STK][1].get_polynomial()

        res = Polynomial.copy(a_poly)
        if opcode == opcodes.ADD:
            res.add(b_poly)
        elif opcode == opcodes.SUB:
            res.sub(b_poly)
        else:
            assert False

        origin.polynomial = res
        self.polynomial = res
        return self.polynomial

    def calculate(self) -> None:
        def to_signed(x):
            return x if x < 2**255 else x - 2**256

        inst_opcode = self.inst.opcode
        if inst_opcode not in {
            opcodes.AND,
            opcodes.MUL,
            opcodes.SUB,
            opcodes.DIV,
            opcodes.SDIV,
            opcodes.MOD,
            opcodes.ADDMOD,
            opcodes.MULMOD,
            opcodes.EXP,
            opcodes.LT,
            opcodes.GT,
            opcodes.SLT,
            opcodes.SGT,
            opcodes.EQ,
            opcodes.ISZERO,
            opcodes.ADD,
            opcodes.OR,
            opcodes.XOR,
            opcodes.NOT,
            opcodes.SHL,
            opcodes.SHR,
            opcodes.SAR,
        }:
            return

        stk_operands = self.operands[STK]
        operand_values = [oprd.value for oprd in stk_operands]

        if None in operand_values:
            # optimize special case
            if inst_opcode not in {
                opcodes.ADD,
                opcodes.SUB,
                opcodes.MUL,
                opcodes.DIV,
                opcodes.SDIV,
                opcodes.AND,
            }:
                return

            if inst_opcode == opcodes.ADD:
                for i in range(2):
                    if operand_values[i] == 0:
                        self.set_origin_value_push_offset(stk_operands[1 - i])
                        return
            elif inst_opcode == opcodes.SUB:
                if operand_values[1] == 0:
                    self.set_origin_value_push_offset(stk_operands[0])
                    return
            elif inst_opcode == opcodes.MUL:
                for i in range(2):
                    if operand_values[i] == 1:
                        self.set_origin_value_push_offset(stk_operands[1 - i])
                        return
                    elif operand_values[i] == 0:
                        self.set_origin_value_push_offset(
                            InstructionInstance.from_value(0)
                        )
                        return
                    elif operand_values[i] == 0x20:
                        # (x+0x1f) / 20 * 20
                        # upper bound for mem index
                        div = stk_operands[1 - i].get_origin()
                        if (
                            div.inst.opcode == opcodes.DIV
                            and div.operands[STK][1].value == 0x20
                        ):
                            add = div.operands[STK][0].get_origin()
                            if add.inst.opcode == opcodes.ADD:
                                for j in range(2):
                                    if add.operands[STK][j].value == 0x1F:
                                        origin = add.operands[STK][1 - j].get_origin()
                                        self.set_origin_value(origin)
                                        assert (
                                            origin.value is None
                                            and origin.push_offset is None
                                        )
                                        return
            elif inst_opcode in {opcodes.DIV, opcodes.SDIV}:
                if operand_values[1] == 1:
                    self.set_origin_value_push_offset(stk_operands[0])
                    return
                elif 0 in operand_values:
                    self.set_origin_value_push_offset(InstructionInstance.from_value(0))
            elif inst_opcode == opcodes.AND:

                def get_and_origin():
                    for m in range(2):
                        if operand_values[m] == 2**256 - 1:
                            return stk_operands[1 - m].get_origin()
                        if operand_values[m] == 2**160 - 1:
                            other = stk_operands[1 - m].get_origin()
                            if other.inst.opcode in {
                                opcodes.ADDRESS,
                                opcodes.CALLER,
                                opcodes.ORIGIN,
                                opcodes.COINBASE,
                            }:
                                return other
                            elif other.inst.opcode == opcodes.AND:
                                for n in range(2):
                                    if other.operands[STK][n].value == 2**160 - 1:
                                        return other
                    return None

                origin = get_and_origin()
                if origin is not None:
                    self.set_origin_value_push_offset(origin)
                    return
        else:
            if inst_opcode == opcodes.ADD:
                value = (operand_values[0] + operand_values[1]) % (2**256)
            elif inst_opcode == opcodes.MUL:
                value = (operand_values[0] * operand_values[1]) % (2**256)
            elif inst_opcode == opcodes.SUB:
                value = (operand_values[0] - operand_values[1]) % (2**256)
            elif inst_opcode == opcodes.DIV:
                try:
                    value = (operand_values[0] // operand_values[1]) % (2**256)
                except ZeroDivisionError:
                    value = 0
            elif inst_opcode == opcodes.SDIV:
                value = None
            elif inst_opcode == opcodes.MOD:
                try:
                    value = (operand_values[0] % operand_values[1]) % (2**256)
                except ZeroDivisionError:
                    value = 0
            elif inst_opcode == opcodes.ADDMOD:
                try:
                    value = (operand_values[0] + operand_values[1]) % operand_values[2]
                except ZeroDivisionError:
                    value = 0
            elif inst_opcode == opcodes.MULMOD:
                try:
                    value = (operand_values[0] * operand_values[1]) % operand_values[2]
                except ZeroDivisionError:
                    value = 0
            elif inst_opcode == opcodes.EXP:
                if operand_values[0] >= 2 and operand_values[1] >= 512:
                    value = None
                else:
                    value = (operand_values[0] ** operand_values[1]) % (2**256)
            elif inst_opcode == opcodes.LT:
                value = int(operand_values[0] < operand_values[1])
            elif inst_opcode == opcodes.GT:
                value = int(operand_values[0] > operand_values[1])
            elif inst_opcode == opcodes.SLT:
                value = int(to_signed(operand_values[0]) < to_signed(operand_values[1]))
            elif inst_opcode == opcodes.SGT:
                value = int(to_signed(operand_values[0]) > to_signed(operand_values[1]))
            elif inst_opcode == opcodes.EQ:
                value = int(operand_values[0] == operand_values[1])
            elif inst_opcode == opcodes.ISZERO:
                value = int(operand_values[0] == 0)
            elif inst_opcode == opcodes.AND:
                value = operand_values[0] & operand_values[1]
            elif inst_opcode == opcodes.OR:
                value = operand_values[0] | operand_values[1]
            elif inst_opcode == opcodes.XOR:
                value = operand_values[0] ^ operand_values[1]
            elif inst_opcode == opcodes.NOT:
                value = operand_values[0] ^ (2**256 - 1)
            elif inst_opcode == opcodes.SHL:
                value = (operand_values[1] << operand_values[0]) % (2**256)
            elif inst_opcode == opcodes.SHR:
                value = (operand_values[1] >> operand_values[0]) % (2**256)
            elif inst_opcode == opcodes.SAR:
                value = (to_signed(operand_values[1]) >> operand_values[0]) % (2**256)
            else:
                assert False

            self.value = value

            if value in operand_values:
                idx = operand_values.index(value)
                self.set_origin_value_push_offset(stk_operands[idx])

    def set_origin_value_push_offset(self, other: InstructionInstance) -> None:
        origin = other.get_origin()
        self.origin = origin
        self.value = origin.value
        self.push_offset = origin.push_offset

    def set_origin_value(self, other: InstructionInstance) -> None:
        origin = other.get_origin()
        self.origin = origin
        self.value = origin.value
