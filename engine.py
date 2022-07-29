from __future__ import annotations
import logging

import disassembler
import tracker
import opcodes
from structures import PathItem, StoItem

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from instruction_instance import InstructionInstance


class Engine:
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.conditions = []
        self.call_values = []
        self.to_addresses = []
        self.todo_keys = []
        self.disasm = disassembler.Disassembler(self.bytecode)
        self.step: int = 0

    def run(self) -> bool:
        self.disasm.disassemble()
        if not (opcodes.special_op & self.disasm.opcodes) and (
            not (opcodes.time_op & self.disasm.opcodes)
            or not (opcodes.mod_op & self.disasm.opcodes)
        ):
            return False
        if opcodes.CALL not in self.disasm.opcodes:
            return False
        logging.info("== first step ==")
        self.step = 1
        self.tracker = tracker.Tracker(self.bytecode, self.disasm, step=self.step)
        self.dfs(start_offset=0, depth=0, step=self.step)
        for attr_name in ("conditions", "to_addresses", "call_values", "todo_keys"):
            attr = getattr(self, attr_name)
            logging.info("%s %s", len(attr), attr_name)
        if (
            not self.conditions
            and not self.call_values
            and not self.to_addresses
            and self.todo_keys
        ):
            logging.info("== second step ==")
            self.step = 2
            self.tracker = tracker.Tracker(
                self.bytecode, self.disasm, step=self.step, todo_keys=self.todo_keys
            )
            self.dfs(start_offset=0, depth=0, step=self.step)
            for attr_name in ("conditions", "to_addresses", "call_values"):
                attr = getattr(self, attr_name)
                logging.info("%s %s", len(attr), attr_name)

        return bool(self.conditions or self.call_values or self.to_addresses)

    def taint_sink(self, step: int, inst_instance: InstructionInstance):
        inst = inst_instance.inst

        if (
            inst.opcode == opcodes.CALL
            and inst_instance.operands[tracker.STK][1].value not in range(1, 10)
            and inst_instance.operands[tracker.STK][2].value != 0
        ):
            to_address = inst_instance.operands[tracker.STK][1].get_origin()
            if to_address.taint_inst & {
                opcodes.CALLER,
                opcodes.ORIGIN,
                opcodes.CALLDATALOAD,
                opcodes.CALLDATACOPY,
            }:
                for item in self.tracker.state.path[:-1]:
                    condition = item.condition
                    if condition is not None and condition.use_special_inst():
                        item = (f"step{step}", condition, inst_instance)
                        self.conditions.append(item)
                call_value = inst_instance.operands[tracker.STK][2]
                if call_value.use_special_inst():
                    self.call_values.append((f"step{step}", inst_instance))

            if to_address.use_special_inst():
                item = (f"step{step}", inst_instance)
                self.to_addresses.append(item)
        elif step == 1 and inst.opcode == opcodes.SSTORE:
            key = inst_instance.operands[tracker.STK][0].get_origin()

            flag = False
            if inst_instance.use_special_inst():
                flag = True
            for item in self.tracker.state.path[:-1]:
                condition = item.condition
                if condition is not None and condition.use_special_inst():
                    inst_instance.taint_inst.update(condition.taint_inst)
                    flag = True
            if flag:
                key_poly = key.get_polynomial()
                for item in reversed(self.todo_keys):
                    if item.key.get_polynomial().eq(key_poly, silence=True):
                        break
                else:
                    self.todo_keys.append(StoItem(key=key, inst_instance=inst_instance))

    def dfs(self, start_offset, depth, step, is_jumpi_true_branch=None):
        if depth > 800:
            logging.warning(
                f"call stack too deep, start_offset={start_offset}, depth={depth}"
            )
            return

        if not self.tracker.update_images(start_offset):
            logging.debug(f"image same, start_offset={start_offset:05x}")
            return

        self.tracker.state.path.append(
            PathItem(start_offset, None, is_jumpi_true_branch)
        )

        pc = self.disasm.at(offset=start_offset).pc
        while True:
            inst = self.disasm.at(pc=pc)
            if inst.opcode not in opcodes.opcodes:
                logging.warning(f"Unknown opcode: {inst.opcode:#02x}")
                break
            pc += 1

            inst_instance = self.tracker.update(inst)
            if inst_instance is None:
                break

            self.taint_sink(step, inst_instance)

            if inst.opcode == opcodes.JUMP:
                target_offset = inst_instance.operands[tracker.STK][0].value
                if target_offset not in self.disasm.invalid_jumpdests:
                    if target_offset in self.disasm.jumpdests:
                        self.dfs(target_offset, depth + 1, step)
                    else:
                        if target_offset is not None:
                            logging.warning(f"Bad jumpdest: {target_offset:#02x}")
                        else:
                            logging.warning("Bad jumpdest: None")

                break
            elif inst.opcode == opcodes.JUMPI:
                target_offset = inst_instance.operands[tracker.STK][0].value
                condition = inst_instance.operands[tracker.STK][1].get_origin()
                self.tracker.state.path[-1].condition = condition
                if target_offset not in self.disasm.invalid_jumpdests:
                    if target_offset in self.disasm.jumpdests:
                        state_cpy = self.tracker.state.copy()
                        self.dfs(target_offset, depth + 1, step, True)
                        self.tracker.state = state_cpy
                        del state_cpy
                    else:
                        if target_offset is not None:
                            logging.warning(f"Bad jumpdest: {target_offset:#02x}")
                        else:
                            logging.warning("Bad jumpdest: None")
                next_offset = self.disasm.at(pc=pc).offset
                assert next_offset == inst.offset + 1
                self.dfs(next_offset, depth + 1, step, False)
                break
            elif inst.is_halt_op():
                break

            # pc already added, this is next instruction
            if self.disasm.at(pc=pc).opcode == opcodes.JUMPDEST:
                next_offset = self.disasm.at(pc=pc).offset
                assert next_offset == inst.offset + 1 + (inst.get_push_arg() or 0)
                self.dfs(next_offset, depth + 1, step)
                break
