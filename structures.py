from __future__ import annotations
import collections
import copy
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from instruction_instance import InstructionInstance


class MemItem:
    def __init__(
        self,
        inst_instance: InstructionInstance,
        start: InstructionInstance,
        length: InstructionInstance,
    ):
        self.inst_instance = inst_instance
        self.start = start
        self.length = length


class StoItem:
    def __init__(
        self,
        key: InstructionInstance,
        inst_instance: InstructionInstance,
        step1_conditions: list[InstructionInstance] | None = None,
    ):
        if step1_conditions is None:
            step1_conditions = []
        self.key = key
        self.inst_instance = inst_instance
        self.step1_conditions = step1_conditions


class Image:
    def __init__(self, stk: list[InstructionInstance]):
        self.stk = tuple((item.push_offset, *sorted(item.taint_inst)) for item in stk)

    def __eq__(self, other: Image):
        if len(self.stk) != len(other.stk):
            return False
        return self.stk == other.stk

    def __hash__(self):
        return hash(self.stk)


class CmpError(Exception):
    pass


class Polynomial:
    def __init__(self, terms=None, cst: int = 0):
        assert cst is not None
        self.d = collections.defaultdict(int)
        # to signed
        self.cst: int = cst if cst < 2**255 else cst - 2**256
        if terms is not None:
            for x in terms:
                self.d[x] += 1

    def cvt(self, x: int) -> int:
        if x >= 2**255:
            x -= 2**256
        elif x < -(2**255):
            x += 2**256
        return x

    def sub(self, other: Polynomial) -> "Polynomial":
        for x, n in other.d.items():
            self.d[x] -= n
        self.cst = self.cvt(self.cst - other.cst)

    def add(self, other: Polynomial) -> "Polynomial":
        for x, n in other.d.items():
            self.d[x] += n
        self.cst = self.cvt(self.cst + other.cst)

    def _cmp(self, other: Polynomial) -> int:
        res = self.__class__.copy(self)
        res.sub(other)
        pos = neg = 0
        for n in res.d.values():
            if n > 0:
                pos += 1
            elif n < 0:
                neg += 1
        if res.cst > 0:
            pos += 1
        elif res.cst < 0:
            neg += 1
        if pos and not neg:
            return 1
        elif neg and not pos:
            return -1
        elif not pos and not neg:
            return 0
        else:
            raise CmpError

    def eq(self, other: Polynomial, silence=False) -> int:
        try:
            return self._cmp(other) == 0
        except CmpError:
            if silence:
                return False
            else:
                raise

    def __eq__(self, _) -> bool:
        raise NotImplementedError

    def __hash__(self) -> bool:
        raise NotImplementedError

    @classmethod
    def copy(cls, poly: Polynomial) -> Polynomial:
        new_poly = Polynomial()
        new_poly.d.update(poly.d)
        new_poly.cst = poly.cst
        return new_poly


class State:
    def __init__(
        self,
        stk=None,
        mem=None,
        sto=None,
        path=None,
        trace=None,
        mem_head=None,
        mem_head_len=4,
        fmps=None,
        fmpids=None,
    ):
        if stk is None:
            stk = []
        if mem is None:
            mem = []
        if sto is None:
            sto = []
        if path is None:
            path = []
        if trace is None:
            trace = []
        if mem_head is None:
            mem_head = [None] * mem_head_len
        if fmps is None:
            fmps = []
        if fmpids is None:
            fmpids = []
        self.stk: list[InstructionInstance] = stk
        self.mem: list[list[MemItem]] = mem
        self.sto: list[StoItem] = sto
        self.path: list[PathItem] = path
        self.trace: list[InstructionInstance] = trace
        self.mem_head: list[MemItem] = mem_head
        self.mem_head_len = mem_head_len
        self.fmps: list[InstructionInstance] = fmps
        self.fmpids: list[int] = fmpids

    def copy(self) -> State:
        state_cpy = State(
            stk=copy.copy(self.stk),
            mem=[copy.copy(x) for x in self.mem],
            sto=copy.copy(self.sto),
            path=copy.copy(self.path),
            trace=copy.copy(self.trace),
            mem_head=copy.copy(self.mem_head),
            mem_head_len=self.mem_head_len,
            fmps=copy.copy(self.fmps),
            fmpids=copy.copy(self.fmpids),
        )
        return state_cpy


class PathItem:
    def __init__(
        self,
        offset: int,
        condition: InstructionInstance | None = None,
        is_jumpi_true_branch: bool | None = None,
    ):
        self.offset = offset
        self.condition = condition
        self.is_jumpi_true_branch = is_jumpi_true_branch

    def to_json(self) -> collections.OrderedDict:
        if self.is_jumpi_true_branch is not None:
            return collections.OrderedDict(
                offset=hex(self.offset),
                from_jumpi_branch=self.is_jumpi_true_branch,
                condition=self.condition,
            )
        else:
            return collections.OrderedDict(
                offset=hex(self.offset), condition=self.condition
            )

    def __repr__(self) -> str:
        return f"{self.offset:05x} {self.condition.value if self.condition is not None else None} {self.is_jumpi_true_branch}"

    def get_range(self):
        return self.start, self.end

    def get_origin(self):
        return self.inst_instance.get_origin()

    def __eq__(self, other):
        return (self.inst_instance, self.start, self.end) == (
            other.inst_instance,
            other.start,
            other.end,
        )

    def eq(self, other):
        return (
            self.inst_instance.eq(other.inst_instance)
            and self.start.eq(other.start)
            and self.end.eq(other.end)
        )
