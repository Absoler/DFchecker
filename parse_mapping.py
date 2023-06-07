#!/usr/local/bin/python3
from bisect import bisect_right
import sys
import json
from iced_x86 import Instruction, Register
from register_mapping import iced_dwarf_regMap, dwarf_iced_regMap

class Var:
    def __init__(self, startFirst:bool = True) -> None:
        self.startFirst = startFirst

        self.offset = 0
        self.regs = {}
        
        self.reg = 128
        
        self.type = -1
        self.startpc = 0
        self.endpc = 0
        self.piece_start = 0
        self.piece_size = 0

        self.name = ""
        self.decl_file = ""
    
        
    def __lt__(self, v):
        return (self.startFirst and (self.startpc < v.startpc or (self.startpc == v.startpc and self.endpc < v.endpc))) \
            or (not self.startFirst and (self.endpc < v.endpc or (self.endpc == v.endpc and self.startpc < v.startpc)))
    
    def __eq__(self, v) -> bool:
        return self.startpc == v.startpc and self.endpc == v.endpc
    
    def __hash__(self) -> int:
        return hash(self.name + "+" + self.decl_file)
    
    def match(self, ins:Instruction) -> int:
        '''
            match type:
            0. not match
            1. address matched
            2. address reg matched
            3. reg match
            4. constant match
        '''
        
        scale_index, scale_base = ins.memory_index_scale, 1
        
        reg_index = iced_dwarf_regMap[ins.memory_index] if ins.memory_index != Register.NONE else -1
        reg_base = iced_dwarf_regMap[ins.memory_base] if ins.memory_base != Register.NONE and ins.memory_base != Register.RIP else -1
        
        offset = ins.memory_displacement

        if self.type == 1:
            return 3 if self.reg == reg_index or self.reg == reg_base else 0
        
        elif self.type == 2:
            return 4 if self.offset == offset else 0
        
        else:
            
            
            
            # reg check
            if type(self.regs) == dict:
                reg_match = True
                if reg_index != -1 and (reg_index not in self.regs[reg_index] or self.regs[reg_index] != scale_index):
                    reg_match = False
                
                if reg_base != -1 and (reg_base not in self.regs[reg_base] or self.regs[reg_base] != scale_base):
                        reg_match = False

                for reg in self.regs:
                    if reg != reg_index and reg != reg_base:
                        reg_match = False
                    elif reg == reg_index and self.regs[reg] != scale_index:
                        reg_match = False
                    elif reg == reg_base and self.regs[reg] != scale_base:
                        reg_match = False
            
            else:
                reg_match = False
            
            offset_match = offset == self.offset

            if reg_match and offset_match:
                return 1
            elif reg_match:
                return 2
            else:
                return 0







count = 0    

class VarMgr:
    
    def __init__(self) -> None:
        self.vars:list[Var] = []
        self.second_vars:list[Var] = []

    def load(self, path:str):
        self.vars.clear()
        with open(path, "r") as f:
            self.addrs = json.loads(f.read())
        
        '''
        {
            "addrExps" : [
                <AddressExp>
            ]
            "name" : <string>
            "decl_file" : <string>
            "decl_row"  : <Dwarf_Unsigned>
            "decl_col"  : <Dwarf_Unsigned>
            "piece_num" : <int>
            "valid" : <bool>
        }

        AddressExp:

        {
            "offset" : <Dwarf_Unsigned>
            "regs" : {
                <int>(reg_ind) : <int>(scale),
            }
            "valid" : <bool>
            "empty" : <bool>

            "type" : <int>
            "startpc" : <Dwarf_Addr>
            "endpc" : <Dwarf_Addr>
            "reg" : <Dwarf_Half>
            
            "piece_start" : <Dwarf_Addr>,
            "piece_size" : <int>
        }
        '''

        for addr in self.addrs:
            if "addrExps" not in addr:
                continue
            for addrExp in addr["addrExps"]:
                if "valid" not in addrExp or not addrExp["valid"]:
                    continue
                var:Var = Var()
                var.name = addr["name"]
                var.decl_file = addr["decl_file"]
                var.startpc = addrExp["startpc"]
                var.endpc = addrExp["endpc"]
                var.offset = addrExp["offset"]
                
                var.regs = addrExp["regs"]
                if var.regs:
                    var.regs = {int(reg) : var.regs[reg] for reg in var.regs}
                
                var.type = addrExp["type"]
                var.reg = addrExp["reg"]
                var.piece_start = addrExp["piece_start"]
                var.piece_size = addrExp["piece_size"]

                self.vars.append(var)
        
        print(f"load {path} done!", file=sys.stderr)

        self.vars.sort()
        
        self.globals = []
        for i in range(0, len(self.vars)):
            if self.vars[i].startpc == 0 and self.vars[i].endpc == 0:
                self.globals.append(self.vars[i])
            else:
                break
    
    def find(self, pos:int, varName:str = "", varNameLst:list[str] = [], decl_file:str = "") -> set[Var]:
        res = set()
        puppet = Var()
        puppet.startpc = pos
        start_ind = bisect_right(self.vars, puppet) # find the right bound
        for i in range(start_ind-1, 0, -1):
            if self.vars[i].startpc <= pos and self.vars[i].endpc>pos:
                res.add(self.vars[i])
            
            if pos - self.vars[i].startpc > 0x20000:
                break
        
        for g in self.globals:
            res.add(g)

        # use varName
        if varName != "":
            res = set([var for var in res if var.name == varName])
        
        if len(varNameLst):
            res = set([var for var in res if var.name in varNameLst])

        # use decl_file
        if decl_file != "":
            res = set([var for var in res if var.decl_file == decl_file])
        
        return res


# mgr = VarMgr()
# mgr.load("varLocator/linux-def_var.json")
# mgr.find(18446744071578846849)
