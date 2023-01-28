#! /usr/bin/python3
import sys
path_of_pyelftools = "/root/pyelftools/"
sys.path.insert(0, path_of_pyelftools)
from elftools.elf.elffile import ELFFile

from iced_x86 import *
import json
import time
import os
import re

normalCheck_mask = 0x1
ifMultiCmp_mask = 0x2
ifRefresh_mask = 0x4

sourcePrefix = ""
objdumpPath = "/root/binutils-gdb/build/binutils/objdump"

#   -------------------------------------------
#   
#   args[1]: binary file to be detected
#   args[2]: json file, recording src_path and problematic line number(s)
#   args[3]: check option
#
#   -------------------------------------------

hexChars = '0123456789abcdef'
ip_offset = 0x50

def create_enum_dict(module):
    ''' for descript iced_x86 int attributes
    '''
    return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}

# reg_to_str = create_enum_dict(Register)
op_access_to_str = create_enum_dict(OpAccess)
code_to_str = create_enum_dict(Code)
opKindDict = create_enum_dict(OpKind)

def hasMem(instr) -> bool:
    # lea inst doesn't access the memory
    if instr.mnemonic == Mnemonic.LEA:
        return False
    for i in range(instr.op_count):
        if(instr.op_kind(i) == OpKind.MEMORY):
            return True
    return False

def is_read(mem:UsedMemory) -> bool:
    return mem.access == OpAccess.READ or mem.access == OpAccess.READ_WRITE\
        or mem.access ==OpAccess.COND_READ or mem.access == OpAccess.READ_COND_WRITE

def sameMem(i:Instruction, j:Instruction) -> bool:
    if  i.memory_base == Register.RIP and \
        j.memory_base == Register.RIP and \
        i.memory_displacement == j.memory_displacement:
        return True
    if  i.memory_base == j.memory_base and \
            i.memory_index == j.memory_index and \
            i.memory_index_scale == j.memory_index_scale and \
            i.memory_displacement == j.memory_displacement:
        return True
    return False


class SourceFile:
    def __init__ (self, name:str):
        self.name = name
        
        '''
        problematic lines, double fetches may happen in the lines indicated by the inner list
        [ [int ], [int ] .. ]   inner list's length may be 1 or 2
        '''
        self.lineGroups:list[list[int]] = []

    
    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, file) -> bool:
        return self.name == file.name

    def setLine(self, lineStrs:list) -> None:
        '''
        parse lineStrs: [str] belong to this file and record problematic lines
        '''
        if len(lineStrs) == 0:
            # no problematic line(s)
            return
        for s in lineStrs:
            if len(s) == 0:
                print("lack info in json lineStr", file=sys.stderr)
                continue
            if " " in s:
                lineNum = [int(no) for no in s.split()]
            else:
                lineNum = [int(s)]

            self.lineGroups.append(lineNum)
    


srcs_mp:dict[str, SourceFile] = {} 

class Result:
    def __init__ (self):
        self._lineNo = -1
        self._srcName = ""
        self.inst_i = None
        self.inst_j = None

    @property
    def lineNo(self):
        return self._lineNo
    @lineNo.setter
    def lineNo(self, value:int):
        self._lineNo = value
    
    @property
    def srcName(self):
        return self._srcName
    @srcName.setter
    def srcName(self, value:str):
        self._srcName = value

    def __repr__(self) -> str:
        info = f"problem at {self._srcName}:{self._lineNo}\n"
        info += f"{self.inst_i.ip:X} {self.inst_i}\n"
        info += f"{self.inst_j.ip:X} {self.inst_j}\n"
        return info


class InstSet:
    '''
    record instrucions corrsponded with a line of a source file
    '''
    def __init__ (self, srcName:str, lineNo:int):
        self.srcName = srcName
        self.lineNo = lineNo
        self.insts:list[Instruction] = []

    def addIns(self, ins:Instruction):
        self.insts.append(ins)
    
    def conflict(self, other = None) -> list[Result]:
        if other == None:
            other = self
        reses = []
        factory = InstructionInfoFactory()
        for i in self.insts:
            for j in other.insts:
                if not i is j and hasMem(i) and hasMem(j) and sameMem(i, j)\
                    and len(factory.info(i).used_memory()) > 0 and is_read(factory.info(i).used_memory()[0])\
                    and len(factory.info(j).used_memory()) > 0 and is_read(factory.info(j).used_memory()[0])\
                    and abs(i.ip-j.ip) < ip_offset:
                    res = Result()
                    res.srcName = self.srcName
                    res.lineNo = self.lineNo
                    res.inst_i = i
                    res.inst_j = j
                    reses.append(res)
        return reses
                    
pos_instsMap: dict[tuple[str, int], InstSet] = {}

'''
    add tolerance for line number(s)
'''
def expand(lst: list[int], err = 3):
    if len(lst) == 0:
        return []
    # mxLine = max(lst)
    errElems = [ val + i for i in range(1, err+1) for val in lst] + \
        [ val - i for i in range(1, err+1) for val in lst]
    # errElems = [ elem for elem in errElems if elem > 0 and elem < mxLine]
    errElems = [ elem for elem in errElems if elem > 0 ]
    return list(set( lst + errElems ))


def parse_Objdump(elf_path:str, allFunc:set[str]):
    pc_PosMap: dict[int, tuple[str, int]] = {}
    '''
    parse my-objdump's output, get the correpondence between instruction address
    and line number.

    my-objdump's output is like:

    func1();
    file:line
    0
    2
    ...
    func2();

    '''
    funcFlag = ";"
    lineFlag = ":"
    
    lines = []
    if os.path.exists(f"{elf_path}.raw"):
        with open(f"{elf_path}.raw", "r") as f:
            print("using objdump cache...", file=sys.stderr)
            lines = f.readlines()
    else:
        lines = os.popen(f"{objdumpPath} -dl {elf_path}").readlines()
    curFunc = ""
    curFile, lineNo = "", -1
    curAddr = -1 
    for i, line in enumerate(lines):
        line = line.strip()
        if len(line) == 0:
            continue
        # if no "()" then "demangle" in line
        if funcFlag in line:
            curFunc = re.findall(r'(.*)\(\)', line)[0]  # get string before "()"
            assert(len(curFunc)>0)
        elif lineFlag in line:
            curFile, lineNo = line.split(":")
            curFile = os.path.abspath(curFile)
            if curFile == "" or lineNo == "":
                # print("lack file info at first or bad output format", file=sys.stderr)
                continue
            lineNo = int(lineNo)
        else:
            if not all ([c in hexChars for c in line]):
                # print("lack file info at first or bad output format", file=sys.stderr)
                continue

            curAddr = int(line, 16)
            
            funcExist = curFunc!=""
            for func in allFunc:
                if curFunc in func:
                    # why `in`? some function may be appended with postfix like 'part', 'isra'
                    funcExist = True
                    break
            '''
            many of disassembly belong to inline funcs from other files (.h e.g.), and now I
            try to avoid them, this may cause no fn because the var-use I care basically
            belong to the current file, not in a function call
            '''
            
            if funcExist and ".c" in curFile:
                if curAddr not in pc_PosMap:
                # ! readelf can't get `.text` section accurately, and it may mix
                #   with `.text.startup`, so some map may be overrided
                # comments: ip is based on current section, so main() in `.text.startup`
                # may start from 0x0 as the same as func_1() in `text`   
                    pc_PosMap[curAddr] = (curFile, lineNo)
        
    return pc_PosMap

def check_loads(elf:ELFFile, elf_path:str, checkGuide:str, option:int):
    '''
    check whether there's compiler-introduced double fetch
    ### conditions:
    1. duplicate address used in instructions from the same line
    '''

    # some important vars
    objdumpPath = "/root/binutils-gdb/build/binutils/objdump"
    startTime = 0
    # some control options
    showDisas = False
    error = 2   # permissible lineNo error
    special_error = 10 # for special check, relax restrictions
    showTime = False

    normalCheck = option & 0x1
    need_checkIfMultiCmp = option & 0x2
    need_checkIfRefresh = option & 0x4

    '''
    process guide file from coccinelle's match result, the format is:

    [ src_file:str, [ lineNo:int | "lineNo lineNo ..." ] ]
    
    file should be the absolute path
    '''
    if showTime:
        startTime = time.time()

    lineGroups_map = {} # { file.c -> [ [int ], [int ] .. ] }
    # lines_special = []  #  [int], for special check
    for lineNo in open(checkGuide, "r+"):
        if len(lineNo.strip()) == 0:
            continue
        inputLine = json.loads(lineNo)
        assert(len(inputLine)==2)
        
        fileName = os.path.abspath(inputLine[0])
        if fileName not in srcs_mp:
            srcs_mp[fileName] = SourceFile(fileName)
        
        srcs_mp[fileName].setLine(inputLine[1])

        # for i, group in enumerate(lineGroups):
        #     for lineNo in group[:]:
        #         for err in range(1, error+1):
        #             lineGroups[i].append(lineNo+err)
        #             lineGroups[i].append(lineNo-err)
        #     lineGroups[i] = list(set(group))
        #     for lineNo in group[:]:
        #         for err in range(1, special_error+1):
        #             lines_special.append(lineNo+err)
        #             lines_special.append(lineNo-err)
        # lines_special = list(set(lines_special))

    if showTime:
        print(f'process guide file: {time.time()-startTime:.6}s')


    # init all instSet, only for those are relative to problematic line(s)
    for srcName in srcs_mp:
        allLineNos = expand(sum(srcs_mp[srcName].lineGroups, []))
        for lineNo in allLineNos:
            pos_instsMap[srcName, lineNo] = InstSet(srcName, lineNo)

    
    pc_instMap = {}
    pcs = []    # addresses of all instructions, sorted
    insts = []  # all instructions, sorted

    line_instMap = {}   # int -> list[Instruction]
    problems = {}        # str -> set(int) # can't use set(Instruction) because two instruction with the same function at different ip would be equal

    allFunc = set()  # set(str) save all function names from symtable
    symsec = elf.get_section_by_name(".symtab")
    if not symsec:
        print("no .symtab in elf", file=sys.stderr)
        return
    for sym in symsec.iter_symbols():   # forget, may avoid inline?
        if "STT_FUNC" == sym['st_info']['type']:
            allFunc.add(sym.name)


    if showTime:
        print(f'get func names: {time.time()-startTime:.6}s')

    text = elf.get_section_by_name('.text')
    code_addr = text['sh_addr']
    
    code = text.data()
    if len(code) == 0:
        code = text.stream.read()
        print("text.data() failed", file=sys.stderr)
        
    decoder = Decoder(64, code, ip=code_addr)
    if not decoder.can_decode:
        print("can't decode code", file=sys.stderr)
        return
    formatter = Formatter(FormatterSyntax.GAS)
    
   

    pc_posMap = parse_Objdump(elf_path, allFunc)



    count, lose = 0, 0
    for instr in decoder:
        count +=1
        
        if instr.ip not in pc_posMap:
            # print(f"lose {instr.ip:X}")
            lose+=1
            continue
        pos = pc_posMap[instr.ip]
        if pos in pos_instsMap:
            pos_instsMap[pos].addIns(instr)

        # pcs.append(instr.ip)

        # pc_instMap[instr.ip] = instr
        # if line not in line_instMap.keys():
        #     line_instMap[line] = []
        # line_instMap[line].append(instr)


        if showDisas:
            dumpInstr = f'{instr.ip:<4X}: {formatter.format(instr):<30}'
            print(dumpInstr)
    # print(f"lose {lose}/{count}")
    if showTime:
        print(f'process {count} insts: {time.time()-startTime:.6}s')

    # pcs.sort()
    # for pc in pcs:
    #     insts.append(pc_instMap[pc])
    

    factory = InstructionInfoFactory()
    

    # mx = max(line_instMap.keys())
    # if normalCheck:
    #     for group in lineGroups:
    #         inslst = []
    #         for line in group:
    #             if line in line_instMap.keys() and line != mx:
    #                 inslst.extend(line_instMap[line])

    #         for i in inslst:
    #             for j in inslst:
    #                 if not i is j and hasMem(i) and hasMem(j) and sameMem(i, j)\
    #                     and len(factory.info(i).used_memory()) > 0 and is_read(factory.info(i).used_memory()[0])\
    #                     and len(factory.info(j).used_memory()) > 0 and is_read(factory.info(j).used_memory()[0]):
    #                     groupDesc = "-".join([str(v) for v in group])
    #                     if groupDesc not in problems:    # use some line in group as index
    #                         problems[groupDesc] = set()
    #                     problems[groupDesc].add(i.ip)
    #                     problems[groupDesc].add(j.ip)

    # print(srcs_mp["/root/linux-6.0-rc6/drivers/input/serio/i8042.c"].lineGroups)
    # test_insts=pos_instsMap["/root/linux-6.0-rc6/drivers/input/serio/i8042.c", 408]
    # print(len(test_insts.insts))
    # for inst in test_insts.insts:
    #     print(inst)

    if normalCheck:
        reses = []
        for srcName in srcs_mp:
            src = srcs_mp[srcName]
            for group in src.lineGroups:
                if len(group) == 1:
                    group = expand(group, err=3)
                    for lineNo in group:
                        if (srcName, lineNo) not in pos_instsMap:
                            continue
                        insts:[Instruction] = pos_instsMap[srcName, lineNo]
                        reses.extend(insts.conflict())

                elif len(group) == 2:
                    group0, group1 = expand([group[0]], err=1), expand([group[1]], err=1)
                    for line0 in group0:
                        insts_0:[Instruction] = pos_instsMap[srcName, line0]
                        for line1 in group1:
                            insts_1:[Instruction] = pos_instsMap[srcName, line1]
                            reses.extend(insts_0.conflict(insts_1))

                else:
                    assert(0)
        




    
    # for i, pc in enumerate(pcs):
    #     if pc in pc_lineMap and pc_lineMap[pc] in lines_special:
    #         if need_checkIfMultiCmp and checkIfMultiCmp(i, insts, code_to_str, opKindDict, pc_lineMap) or\
    #             need_checkIfRefresh and checkIfRefresh(i, insts, code_to_str, opKindDict):
    #             line_str = str(pc_lineMap[pc])
    #             if line_str not in problems:
    #                 problems[line_str] = set()
    #             problems[line_str].add(pc)

    if showTime:
        print(f'analysis: {time.time()-startTime:.6}')

    # if problems:
    #     print(inputLine)
    #     for line in problems.keys():
    #         print("problematic line(s): " + line)
    #         for ip in problems[line]:
    #             instr = pc_instMap[ip]
    #             disas = formatter.format(instr)
    #             print(f"{instr.ip:<4X}: {disas:<30} {pc_lineMap[instr.ip]}")
    #     print("")
    #     exit(1)
    for res in reses:
        print(res)

def checkIfMultiCmp(index:int, insts:list, code_to_str:dict, opkind_to_str:dict, pc_lineMap:dict):
    if not ( (code_to_str[insts[index].code].startswith("MOV") and "MEMORY" in opkind_to_str[insts[index].op1_kind]) or \
        (code_to_str[insts[index].code].startswith("CMP") and \
        ("MEMORY" in opkind_to_str[insts[index].op0_kind] or "MEMORY" in opkind_to_str[insts[index].op1_kind])) ) :
        return False

    output = 0
    nextLoadInd = -1    # index of next cmp/mov inst which accesses the same memory
    segRange = 10    # max distance accepted between two cmp/mov
    for i in range(index+1, min(index+segRange, len(insts)) ):
        if not ( (code_to_str[insts[i].code].startswith("MOV") and "MEMORY" in opkind_to_str[insts[i].op1_kind]) or \
            (code_to_str[insts[i].code].startswith("CMP") and \
            ("MEMORY" in opkind_to_str[insts[i].op0_kind] or "MEMORY" in opkind_to_str[insts[i].op1_kind])) ):
            continue

        if sameMem(insts[index], insts[i]):
            nextLoadInd = i
            break
    
    if nextLoadInd == -1:
        return False
    
    firstFeat, secondFeat = -1, -1
    for i in range(index, min(index+segRange, len(insts)) ):
        if code_to_str[insts[i].code].startswith("SBB") or\
            code_to_str[insts[i].code].startswith("CMOV") or\
            code_to_str[insts[i].code].startswith("SET") or\
            code_to_str[insts[i].code].startswith("SAR"):
            firstFeat = i
            break

    for i in range(nextLoadInd, min(nextLoadInd+segRange, len(insts)) ):
        if i == firstFeat:
            continue
        if code_to_str[insts[i].code].startswith("SBB") or\
            code_to_str[insts[i].code].startswith("CMOV") or\
            code_to_str[insts[i].code].startswith("SET") or\
            code_to_str[insts[i].code].startswith("SAR"):
            secondFeat = i
            break
    
    if firstFeat == -1 or secondFeat == -1:
        return False

    if insts[index].ip in pc_lineMap and insts[nextLoadInd].ip in pc_lineMap and\
        abs(pc_lineMap[insts[index].ip] - pc_lineMap[insts[nextLoadInd].ip]) > 0:
        return False

    if output:
        print(f"nextLoad is {insts[nextLoadInd]}")
    return True

class MemInfo:
        def __init__(self, isGlobal:bool, base, index, scale, disp, isRead:bool) -> None:
            '''
            address of global object is `rip + offset`, we save this value in self.disp
            address of local object is `base+scale*index+disp`
            '''
            self.isGlobal = isGlobal
            self.base = base
            self.index = index
            self.scale = scale
            self.disp = disp
            self.isRead = isRead

        def __eq__(self, mem) -> bool:
            if self.isGlobal:
                return self.disp == mem.disp
            return self.base == mem.base and \
            self.index == mem.index and \
            self.disp == mem.disp and \
            self.scale == mem.scale and \
            self.isRead == mem.isRead


def checkIfRefresh(index:int, insts:list, codeDict:dict, opKindDict:dict) -> bool:
    interval = 8
    
    # mov - cmov - mov
    if codeDict[insts[index].code].startswith("MOV") and opKindDict[insts[index].op0_kind] == "REGISTER":
        
        # try find cmov
        reg = insts[index].op0_register

        cmov_list = [] # index: ints

        hit = [] # (hit_cmov, hit_mov)

        for i in range(index+1, min(len(insts), index+interval)):
            if not codeDict[insts[i].code].startswith("CMOV"):
                continue

            if not "MEMORY" in opKindDict[insts[i].op1_kind]:
                continue
            if not "REGISTER" in opKindDict[insts[i].op0_kind]:
                continue

            cmov_reg = insts[i].op0_register
            if cmov_reg != reg:
                continue
            
            cmov_list.append(i)
        
        if len(cmov_list) == 0:
            return False
        
        for i in cmov_list:
            for j in range(i+1, min(len(insts), index+interval)):
                if not codeDict[insts[j].code].startswith("MOV"):
                    continue
                
                if not "REGISTER" in opKindDict[insts[j].op1_kind]:
                    continue
                badmov_reg = insts[j].op1_register
                if badmov_reg != reg:
                    continue
                
                if not "MEMORY" in opKindDict[insts[j].op0_kind]:
                    continue

                if not sameMem(insts[i], insts[j]):
                    continue
                
                hit.append((index, i, j))
        
        if len(hit)!=0:
            return True
        return False


    # jmp - mov - mov
    elif codeDict[insts[index].code].startswith("J"):
        
        hit = None

        jmp_kind = opKindDict[insts[index].op0_kind].lower()
        jmp_val = getattr(insts[index], jmp_kind)

        # find first mov (addr), reg
        interval = 8

        load_mov_list = []

        for i in range(index+1, min(len(insts), index+interval)):
            if not codeDict[insts[i].code].startswith("MOV"):
                continue

            if not "MEMORY" in opKindDict[insts[i].op1_kind]:
                continue
            if not "REGISTER" in opKindDict[insts[i].op0_kind]:
                continue
            
            load_mov_list.append(i)
        
        for i in load_mov_list:
            for j in range(i+1, min(len(insts), index+interval)):
                if not codeDict[insts[j].code].startswith("MOV"):
                    continue
                
                if not "REGISTER" in opKindDict[insts[j].op1_kind]:
                    continue
                if insts[j].op1_register != insts[i].op0_register:
                    continue
                
                if not "MEMORY" in opKindDict[insts[j].op0_kind]:
                    continue
                if not sameMem(insts[i], insts[j]):
                    continue

                if jmp_val < insts[j].ip:
                    continue

                hit = (index, i, j)
        
        if hit is not None:
            return True
        return False

    
    return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        exit(0)
    file = open(sys.argv[1], "rb")
    elf = ELFFile(file)

    option = int(sys.argv[3], 16)

    check_loads(elf, sys.argv[1], sys.argv[2], option)
    file.close()
