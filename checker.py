#! /usr/bin/python3
import sys
import argparse
path_of_pyelftools = "/home/pyelftools/"
sys.path.insert(0, path_of_pyelftools)
from elftools.elf.elffile import ELFFile

from iced_x86 import *
import json
import time
import os
import re
import bisect

normalCheck_mask = 0x1
ifMultiCmp_mask = 0x2
ifRefresh_mask = 0x4

permit_relocatable:bool = True
is_relocatable:bool = False

sourcePrefix = ""
objdumpPath = "/home/binutils-gdb/build/binutils/objdump"

#   -------------------------------------------
#   
#   args[1]: binary file to be detected
#   args[2]: json file, recording src_path and problematic line number(s)
#   args[3]: check option, default as 0x1
#
#   -------------------------------------------

hexChars = '0123456789abcdef'
ip_offset = 0x40

def create_enum_dict(module):
    ''' for descript iced_x86 int attributes
    '''
    return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}

# reg_to_str = create_enum_dict(Register)
op_access_to_str = create_enum_dict(OpAccess)
code_to_str = create_enum_dict(Code)
opKind_to_str = create_enum_dict(OpKind)

all_insts = []  # all instructions, sorted

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
        ( i.memory_displacement == j.memory_displacement or (permit_relocatable and is_relocatable ) ):
        return True
    if  i.memory_base == j.memory_base and \
            i.memory_index == j.memory_index and \
            i.memory_index_scale == j.memory_index_scale and \
            i.memory_displacement == j.memory_displacement:
        return True
    return False


class SourceFile:
    '''
    guide info from `.json` file
    '''
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
        assert(type(lineStrs) == list)
        if len(lineStrs) == 0:
            # no problematic line(s)
            return
        for s in lineStrs:
            if len(s) == 0:
                print("lack info in json lineStr", file=sys.stderr)
                continue
            if " " in s:
                lineNum = [int(no) for no in s.split()]
            elif "-" in s:
                lineNum = [int(no) for no in s.split('-')]
            else:
                lineNum = [int(s)]

            self.lineGroups.append(lineNum)
    


srcs_mp:dict[str, SourceFile] = {} 

class Result:
    def __init__ (self, lineNo:int = -1, srcName:str = "", _inst_i:Instruction = None, _inst_j:Instruction = None):
        self._lineNo = lineNo
        self._srcName = srcName
        self.inst_i = _inst_i
        self.inst_j = _inst_j

    def __hash__(self) -> int:
        return hash(self.inst_i) + hash(self.inst_j)

    def __eq__(self, other) -> bool:
        return self._lineNo == other._lineNo and\
            self._srcName == other._srcName and\
            self.inst_i == other.inst_i and\
            self.inst_j == other.inst_j

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

    def simpleMsg(self) -> str:
        info = f"{self._srcName}:{self._lineNo}"
        return info

    def jsonMsg(self) -> str:
        info = {f'{self._srcName}:{self._lineNo}' : [[f"{self.inst_i.ip:X}", f"{self.inst_i}"], [f"{self.inst_j.ip:X}", f"{self.inst_j}"]]}
        return json.dumps(info)
    
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
        self.discriminatorMap:dict[int, int] = {}
        self.realFuncMap:dict[int, str] = {}

    def addIns(self, ins:Instruction, discriminator:int, realFunc:str):
        self.insts.append(ins)
        self.discriminatorMap[ins.ip] = discriminator
        self.realFuncMap[ins.ip] = realFunc
    
    def flowElseWhere(self, inst_i:Instruction, inst_j:Instruction):
        '''
        check whether `jmp` or `call` exists between the i-th and 
        j-th instructions in `insts`, which acess the same memory.

        if yes, we assume this imply no double-fetch happens here
        '''
        i_ind = bisect.bisect_left(all_insts, inst_i.ip, 0, len(all_insts), key = lambda ins : ins.ip)
        j_ind = bisect.bisect_left(all_insts, inst_j.ip, 0, len(all_insts), key = lambda ins : ins.ip)
        if i_ind > j_ind:
            i_ind, j_ind = j_ind, i_ind
        for ind in range(i_ind, j_ind):
            if code_to_str[all_insts[ind].code].startswith("JMP") or\
                code_to_str[all_insts[ind].code].startswith("JN") or\
                code_to_str[all_insts[ind].code].startswith("JE") or\
                code_to_str[all_insts[ind].code].startswith("JA") or\
                code_to_str[all_insts[ind].code].startswith("JB") or\
                code_to_str[all_insts[ind].code].startswith("JG") or\
                code_to_str[all_insts[ind].code].startswith("JL") or\
                code_to_str[all_insts[ind].code].startswith("CALL"):
                return True
        return False

    def usingStack(self, ins: Instruction) -> bool:
        cond1 = ins.memory_base == Register.RSP or ins.memory_base == Register.RBP \
            or ins.memory_index == Register.RSP or ins.memory_index == Register.RBP
        return cond1

    def isIncidentLoad(self, ins:Instruction) -> bool:
        '''     filter instruction such as `add 1, [mem]`
                in `iced_x86.Instruction`, op0 is the dest operand
        '''
        # return False
        code_desc = code_to_str[ins.code]
        cal_prefix = ["ADD", "SUB"]
        for prefix in cal_prefix:
            if code_desc.startswith(prefix) and \
            ins.op_count >= 2 \
            and opKind_to_str[ins.op0_kind].startswith("MEMORY") \
            and not opKind_to_str[ins.op1_kind].startswith("MEMORY"):
                return True
        return False

    def breakByPush(self, ins_i:Instruction, ins_j:Instruction) -> bool:
        # push will modify the value of rbp or rsp, so the next load won't access the same position
        cond1 = code_to_str[ins_i.code].startswith("PUSH") or code_to_str[ins_j.code].startswith("PUSH")
        cond2 = ins_i.memory_base == Register.RBP or ins_i.memory_index == Register.RBP\
        or ins_i.memory_base == Register.RSP or ins_i.memory_index == Register.RSP

        return cond1 and cond2

    def regModified(self, firstInd:int, secondInd:int, insts:list[Instruction]):
        ''' base or index reg used by the first load inst may be modified
            between these two instructions, range: [first, second)
        '''
        if not opKind_to_str [insts[firstInd].op1_kind].startswith("MEMORY"):
            return False
        base, index = insts[firstInd].memory_base, insts[firstInd].memory_index
        for i in range(firstInd, secondInd):
            ins = insts[i]
            if ins.op0_kind == OpKind.REGISTER and\
                (ins.op0_register == base or ins.op0_register == index):
                return True
        return False


    def conflict(self, other = None) -> list[Result]:
        if other == None:
            other = self
        reses = []
        factory = InstructionInfoFactory()
        for i, ins_i in enumerate(self.insts):
            for j, ins_j in enumerate(other.insts):
                if i >= j:
                    continue
                if not ins_i is ins_j and hasMem(ins_i) and hasMem(ins_j) and sameMem(ins_i, ins_j)\
                    and len(factory.info(ins_i).used_memory()) > 0 and is_read(factory.info(ins_i).used_memory()[0])\
                    and len(factory.info(ins_j).used_memory()) > 0 and is_read(factory.info(ins_j).used_memory()[0])\
                    and (self!=other or self.discriminatorMap[ins_i.ip] == self.discriminatorMap[ins_j.ip])\
                    and (self!=other or self.realFuncMap[ins_i.ip] == self.realFuncMap[ins_j.ip])\
                    and abs(ins_i.ip-ins_j.ip) < ip_offset\
                    and not self.breakByPush(ins_i, ins_j)  \
                    and (not self.isIncidentLoad(ins_i)) and (not self.isIncidentLoad(ins_j)) \
                    and not self.flowElseWhere(ins_i, ins_j) \
                    and (not self.usingStack(ins_i) and (not self.usingStack(ins_j))) \
                    and (self != other or not self.regModified(i, j, self.insts)):
                    res = Result(self.lineNo, self.srcName, ins_i, ins_j)
                    reses.append(res)
        return reses
    
    def conflict_in_ifMultiCmp(self):
        reses = []
        for i, inst in enumerate(self.insts):

            firstLoad, secondLoad = checkIfMultiCmp(i, self.insts, code_to_str, opKind_to_str)
            if firstLoad == -1 or secondLoad == -1:
                continue
            if self.usingStack(self.insts[firstLoad]) or self.usingStack(self.insts[secondLoad]):
                continue
        
            if self.realFuncMap[self.insts[firstLoad].ip] != self.realFuncMap[self.insts[secondLoad].ip]:
                continue

            if self.regModified(firstLoad, secondLoad, self.insts):
                continue
            reses.append(Result(self.lineNo, self.srcName, self.insts[firstLoad], self.insts[secondLoad]))
        return reses
              
pos_instsMap: dict[tuple[str, int], InstSet] = {}
'''
    map `fileName, lineNo` to `InstSet`, the crucial info
''' 


def expand(lst: list[int], err = 3):
    '''
        add tolerance for line number(s) in debug info
    '''
    if len(lst) == 0:
        return []
    # mxLine = max(lst)
    errElems = [ val + i for i in range(1, err+1) for val in lst] + \
        [ val - i for i in range(1, err+1) for val in lst]
    # errElems = [ elem for elem in errElems if elem > 0 and elem < mxLine]
    errElems = [ elem for elem in errElems if elem > 0 ]
    return list(set( lst + errElems ))


def parse_Objdump(elf_path:str, allFunc:set[str]) -> dict[int, tuple[str, int, int, str]]:
    pc_dPosMap: dict[int, tuple[str, int, int, str]] = {}
    # print(len(allFunc))
    '''
    parse my-objdump's output, get the correpondence between instruction address
    and line number.

    my-objdump's output is like:

    addr <RealFunc>:
    func1():
    file:lineNo
    0
    2
    ...
    func2():
    file:lineNo (discriminator Num)

    '''
    startTime = time.time()
    
    ''' format: filePath:lineNo (discriminator Num)
    '''
    isFileLine_regex = re.compile(r'\S+:\d+')
    
    ''' format: func1():
    '''
    isFunc_regex = re.compile(r'\S+\(\):')
    
    ''' format: addr <func>:
    '''
    isRealFunc_regex = re.compile(r'[\s\w]*<([\w@\.]+)>:')
    
    ''' format: hexNum
    '''
    isAddress_regex = re.compile(r'^[a-fA-F0-9]+$')
    
    
    def isDebug(feat):
        return feat == "sqlite3BtreeGetAutoVacuum"
        # return False

    lineFlag = ":"
    discriminatorFlag = "discriminator"
    
    lines = []
    if os.path.exists(f"{elf_path}.raw"):
        with open(f"{elf_path}.raw", "r") as f:
            print("using objdump cache...", file=sys.stderr)
            lines = f.readlines()
    else:
        lines = os.popen(f"{objdumpPath} -dl {elf_path}").readlines()
    curRealFunc = ""
    isValidFunc = False
    curFunc = ""
    curFile, lineNo = "", -1
    curAddr = -1 
    curDiscirminator = 1
    
    for i, line in enumerate(lines):
        # if i%2000 == 0:
        #     print(f'    process raw {i}  {time.time()-startTime:.6}s', file=sys.stderr)
        line = line.strip()
        if len(line) == 0:
            continue
        # if no "()" then "demangle" in line
        if isFunc_regex.match(line) and len(line) == isFunc_regex.match(line).span()[1]:
            curFunc = re.findall(r'(.*)\(\)', line)[0]  # get string before "()"
            assert(len(curFunc)>0)
        elif isFileLine_regex.match(line) and line.count(':') == 1:
            curDiscirminator = 1
            pure_line = line
            if discriminatorFlag in line:
                curDiscirminator = int(re.findall(f'\({discriminatorFlag}\s*(\d+)\)', line)[0])
                pure_line = re.sub(f'\s*\({discriminatorFlag}\s*(\d+)\)','',line)
            try:
                curFile, lineNo = pure_line.split(":")
            except ValueError:
                print(f"line {line}\npure_line {pure_line}")
                exit(0)
            curFile = os.path.abspath(curFile)
            if curFile == "" or lineNo == "":
                # print("lack file info at first or bad output format", file=sys.stderr)
                continue
            lineNo = int(lineNo)
        elif isRealFunc_regex.match(line) and isRealFunc_regex.match(line).span()[1] == len(line):
            curRealFunc = isRealFunc_regex.match(line).group(1)
            if ".plt" in curRealFunc or "@plt" in curRealFunc:
                isValidFunc = False
            else:
                isValidFunc = True
            assert(len(curRealFunc)>0)
        else:
            
            if not all ([c in hexChars for c in line]):
                print("unrecognized line: " + line, file=sys.stderr)
                continue

            if not isValidFunc:
                continue

            curAddr = int(line, 16)
            
            funcExist = curFunc!=""
            # for func in allFunc:
            #     if curFunc in func:
            #         # why `in`? some function may be appended with postfix like 'part', 'isra'
            #         funcExist = True
            #         break
            '''
            many of disassembly belong to inline funcs from other files (.h e.g.), and now I
            try to avoid them, this may cause no fn because the var-use I care basically
            belong to the current file, not in a function call
            '''
            # if isDebug(curRealFunc):
            #     print(f"get {curFunc} {funcExist} {curFile}")
            if funcExist and ".c" in curFile:
                if curAddr not in pc_dPosMap:
                # ! readelf can't get `.text` section accurately, and it may mix
                #   with `.text.startup`, so some map may be overrided
                # comments: ip is based on current section, so main() in `.text.startup`
                # may start from 0x0 as the same as func_1() in `text`   
                    pc_dPosMap[curAddr] = (curFile, lineNo, curDiscirminator, curRealFunc)
            
                        
    return pc_dPosMap

def check_loads(elf:ELFFile, args:argparse.Namespace):
    '''
    check whether there's compiler-introduced double fetch
    ### conditions:
    1. duplicate address used in instructions from the same line
    '''

    # cmd control options
    elf_path:str = args.exe
    checkGuide:str = args.guide
    option:int = args.option
    filterBy:str = args.filterBy
    useSimpleGuide:bool = args.useSimpleGuide
    showTime:bool = args.showTime
    showDisas:bool = args.showDisas

    # some important vars
    startTime = 0
    error = 2   # permissible lineNo error
    special_error = 10 # for special check, relax restrictions

    # check type
    normalCheck = option & 0x1
    need_checkIfMultiCmp = option & 0x2
    need_checkIfRefresh = option & 0x4

    no_guide = (checkGuide == "noGuide")
    # only some modes support full scanning
    # only `one line` double fetch check
    assert( need_checkIfMultiCmp or normalCheck )

    '''
    process guide file from coccinelle's match result, the format is:

    [ src_file:str, [ "lineNo" | "lineNo lineNo ..." ] ]
    
    file should be the absolute path
    '''
    if showTime:
        startTime = time.time()

    # lineGroups_map = {} # { file.c -> [ [int ], [int ] .. ] }
    '''
        fill srcs_mp based on given guide info
    '''
    if not no_guide:
        if not useSimpleGuide:
            for lineNo in open(checkGuide, "r+"):
                if len(lineNo.strip()) == 0:
                    continue
                inputLine = json.loads(lineNo)
                assert(len(inputLine)==2)
                
                fileName = os.path.abspath(inputLine[0])
                if fileName not in srcs_mp:
                    srcs_mp[fileName] = SourceFile(fileName)
                
                srcs_mp[fileName].setLine(inputLine[1])
        else:
            ''' must be single file test, may be relocatable file
            '''
            src_path = elf_path.replace(".o", "") + ".c"
            srcs_mp[src_path] = SourceFile(src_path)
            srcs_mp[src_path].setLine([checkGuide])


    if showTime:
        print(f'process guide file: {time.time()-startTime:.6}s', file=sys.stderr)


    

    
    pc_instMap = {}
    pcs = []    # addresses of all instructions, sorted

    line_instMap = {}   # int -> list[Instruction]
    problems = {}        # str -> set(int) # can't use set(Instruction) because two instruction with the same function at different ip would be equal


    '''
        get all function names from symbol table

    '''
    allFunc = set()  # set(str) save all function names from symtable
    symsec = elf.get_section_by_name(".symtab")
    if not symsec:
        print("no .symtab in elf", file=sys.stderr)
        return
    for sym in symsec.iter_symbols():   # forget, may avoid inline?
        if "STT_FUNC" == sym['st_info']['type']:
            allFunc.add(sym.name)

    if showTime:
        print(f'get func names: {time.time()-startTime:.6}s', file=sys.stderr)


    '''
        extract code segment
    '''
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
    
   
    # dpos: position with discriminator and realFunc
    pc_dposMap = parse_Objdump(elf_path, allFunc)
    
    if showTime:
        print(f"parse disassemble with objdump {time.time()-startTime:.6}s", file=sys.stderr)

    '''
    for full scan, fill srcs_mp with all lines  
    '''
    if no_guide:
        temp_srcName_lines: dict[str, set[int]] = {}
        for dpos in pc_dposMap.values():
            srcName, line, _, _ = dpos
            if srcName not in temp_srcName_lines:
                temp_srcName_lines[srcName] = set()
            temp_srcName_lines[srcName].add(line)
        
        for srcName in temp_srcName_lines:
            srcs_mp[srcName] = SourceFile(srcName)
            for line in temp_srcName_lines[srcName]:
                srcs_mp[srcName].setLine([str(line)])

    '''
        init all instSet, only for those are relative to problematic line(s)
        need srcs_mp to know which position are check targets
    '''
    for srcName in srcs_mp:
        allLineNos = expand(sum(srcs_mp[srcName].lineGroups, []))
        for lineNo in allLineNos:
            pos_instsMap[srcName, lineNo] = InstSet(srcName, lineNo)

    '''
        iterate through all insts, for every instrucion
        1. use `pc_dposMap` to get corresponding position [fileName, lineNo]
        2. set this inst in `pos_instsMap` 
    '''
    count, lose = 0, 0
    for instr in decoder:
        all_insts.append(instr)
        count +=1
        
        if instr.ip not in pc_dposMap:
            # print(f"lose {instr.ip:X}")
            lose+=1
            continue
        dpos = pc_dposMap[instr.ip]
        srcName, lineNo, discriminator, realFunc = dpos
        
        if (srcName, lineNo) in pos_instsMap:
            pos_instsMap[srcName, lineNo].addIns(instr, discriminator, realFunc)

        if showDisas:
            dumpInstr = f'{instr.ip:<4X}: {formatter.format(instr):<30}'
            print(dumpInstr)
    # print(f"lose {lose}/{count}")
    if showTime:
        print(f'process {count} insts: {time.time()-startTime:.6}s', file=sys.stderr)

    

    
    '''
        start check
    '''
    normalReses:set[Result] = set()
    if normalCheck:
        for srcName in srcs_mp:
            src = srcs_mp[srcName]
            for group in src.lineGroups:
                if len(group) == 1:
                    group = expand(group, err=3)
                    for lineNo in group:
                        if (srcName, lineNo) not in pos_instsMap:
                            continue
                        insts:InstSet = pos_instsMap[srcName, lineNo]
                        curReses = insts.conflict()
                        for res in curReses:
                            normalReses.add(res)

                elif len(group) == 2:
                    group0, group1 = expand([group[0]], err=1), expand([group[1]], err=1)
                    for line0 in group0:
                        insts_0:InstSet = pos_instsMap[srcName, line0]
                        for line1 in group1:
                            insts_1:InstSet = pos_instsMap[srcName, line1]
                            curReses = insts_0.conflict(insts_1)
                            for res in curReses:
                                normalReses.add(res)

                else:
                    assert(0)
    
    ifMultReses:set[Result] = set()
    if need_checkIfMultiCmp:    
        for srcName in srcs_mp:
            src = srcs_mp[srcName]
            for group in src.lineGroups:
                group = expand(group, err=3)
                for lineNo in group:
                    if (srcName, lineNo) not in pos_instsMap:
                        continue
                    insts:InstSet = pos_instsMap[srcName, lineNo]
                    curReses = insts.conflict_in_ifMultiCmp()
                    for res in curReses:
                        ifMultReses.add(res)    


    if showTime:
        print(f'analysis: {time.time()-startTime:.6}', file=sys.stderr)

    if filterBy:
        for line in open(filterBy, "r"):
            pass

    print(f"{len(normalReses) + len(ifMultReses)} warning(s) in total:\n")
    
    print(f"\nnormal check:")
    for res in normalReses:
        print(res.jsonMsg())
        print()
    
    print(f"\nifMultiCmp check:")
    for res in ifMultReses:
        print(res.jsonMsg())
        print()

    if len(normalReses) + len(ifMultReses) > 0:
        return 1
    else:
        return 0

def checkIfMultiCmp(index:int, insts:list[Instruction], code_to_str:dict, opkind_to_str:dict) -> tuple[int, int]:
    if not ( (code_to_str[insts[index].code].startswith("MOV") and "MEMORY" in opkind_to_str[insts[index].op1_kind]) or \
        (code_to_str[insts[index].code].startswith("CMP") and \
        ("MEMORY" in opkind_to_str[insts[index].op0_kind] or "MEMORY" in opkind_to_str[insts[index].op1_kind])) ) :
        return [-1, -1]

    nextLoadInd = -1    # index of next cmp/mov inst which accesses the same memory
    segRange = 10    # max distance accepted between two cmp/mov
    for i in range(index+1, min(index+segRange, len(insts)) ):
        assert(insts[i-1].ip<insts[i].ip)
        if insts[i].ip - insts[index].ip > ip_offset * 2:
            ''' ip's difference shouldn't be too large, too
            '''
            break
        if not ( (code_to_str[insts[i].code].startswith("MOV") and "MEMORY" in opkind_to_str[insts[i].op1_kind]) or \
            (code_to_str[insts[i].code].startswith("CMP") and \
            ("MEMORY" in opkind_to_str[insts[i].op0_kind] or "MEMORY" in opkind_to_str[insts[i].op1_kind])) ):
            continue

        if sameMem(insts[index], insts[i]):
            nextLoadInd = i
            break
    
    if nextLoadInd == -1:
        return [-1, -1]
    
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
        return [-1, -1]

    #! no need because passed-in insts belong to the same position
    # if insts[index].ip in pc_lineMap and insts[nextLoadInd].ip in pc_lineMap and\
    #     abs(pc_lineMap[insts[index].ip] - pc_lineMap[insts[nextLoadInd].ip]) > 0:
    #     return False

    return [index, nextLoadInd]

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", "-e", help="specify analyzed executable file", required=True, type=str)
    parser.add_argument("--guide", "-g", help="specify guide file or nums joined by `-`", required=True)
    parser.add_argument("--option", "-opt", help="analysis choice", default=1, type=int)
    parser.add_argument("--filterBy", "-fb", help="filter result use an existing result file, of single line json format", type=str)
    parser.add_argument("--useSimpleGuide", "-sG", help="use nums joined by `-` to check only one file", action="store_true")
    parser.add_argument("--showTime", "-t", help="show time used in each part", action="store_true")
    parser.add_argument("--showDisas", "-d", help="show disassemble code", action="store_true")
    args:argparse.Namespace = parser.parse_args()
    
    file = open(args.exe, "rb")
    elf = ELFFile(file)

    is_relocatable = str(args.exe).endswith(".o")
    ret = check_loads(elf, args)
    file.close()
    exit(ret)