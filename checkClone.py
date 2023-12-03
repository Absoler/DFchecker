#!/usr/local/bin/python3
import sys, os
import argparse, re
from elftools.elf.elffile import ELFFile
import angr
from iced_x86 import *
from checker import parse_Objdump, code_to_str, hasMem, sameMem, is_read

sys.path.append(f"/home/varviewer/analysis")
from libanalysis import Analysis
from variable import *
from util import *
from rewrite import *
from libresult import *


check_re = re.compile(r'CMP|SUB|TEST|AND|SHL|SAL|ROL|DEC')
cmp_feat_re = re.compile(r'SBB|SAR|CMOV|SET')

def res_str(inst_i:Instruction, inst_j:Instruction, names:list = []):
    return f"{inst_i.ip:X}: {formatter.format(inst_i)}\n" +\
           f"{inst_j.ip:X}: {formatter.format(inst_j)}\n" +\
           f"{names}\n\n\n"


def is_load_memory(inst:Instruction):

    if not hasMem(inst):
        return False
    
    code_str:str = code_to_str[inst.code]
    # if code_str.startswith("CMOV"):
    #     return False

    isLoad = False
    if code_str.startswith("CMP") or code_str.startswith("TEST"):
        isLoad = True
    else:
        isLoad = inst.op_count > 1 and inst.op1_kind == OpKind.MEMORY
    
    return isLoad


def is_check_memory(i:int, insts:list[Instruction]) -> bool:
    
    inst:Instruction = insts[i]
    if inst.code not in code_to_str:
        return False
    
    code_str:str = code_to_str[inst.code]

    # has a load operation
    if not is_load_memory(inst):
        return False
    
    # no `rsp` or `rbp`
    if inst.memory_base == Register.RSP or inst.memory_base == Register.RBP:
        return False

    if check_re.search(code_str):
        return True
    
    if code_str.startswith("MOV") and inst.op1_kind == OpKind.MEMORY:
        reg = inst.op0_register
        for j in range(i+1, i+1+is_check_memory.check_range):
            if j >= len(insts):
                break
            match_reg = False
            inst_j = insts[j]
            for k in range(inst_j.op_count):
                if inst_j.op_kind(k) == OpKind.REGISTER and inst_j.op_register(k) == reg:
                    match_reg = True
                    break
            if match_reg and check_re.search(code_to_str[insts[j].code]):
                return True

    return False

is_check_memory.check_range = 5



def find_clone_pair(insts:list[Instruction]) -> list[tuple[int, int]]:
    ''' constraints:
        1. a variable loaded in two instructions inside a range
            1. test, cmp..
            2. any load
        2. [optional] mapped variable's name doesn't occur in mapped lines
    '''
    ans = []

    # constraint 1
    for i in range(len(insts)):
        ''' first must be check instruction such as cmp or test
        '''
        if not is_check_memory(i, insts):
            continue

        for j in range(i + 1, i + find_clone_pair.inst_range + 1):
            if not is_load_memory(insts[j]):
                continue

            if not sameMem(insts[i], insts[j]):
                continue
            
            ans.append((i, j))

    return ans

find_clone_pair.inst_range = 5



def find_if_pairs(insts:list[Instruction]) -> list[tuple[int, int]]:
    ''' constraints:
        1. double check the same memory location
        2. [optional] `sbb|cmov|set|sar` instrction after check
    '''
    ans = []

    for i in range(len(insts)):
        if not is_check_memory(i, insts):
            continue
            
        for j in range(i + 1, i + find_if_pairs.inst_range + 1):
            if not is_check_memory(j, insts):
                continue

            if not sameMem(insts[i], insts[j]):
                continue
            
            cmp_feat = False
            for k in range(i+1, j):
                k_op_str:str = code_to_str[insts[k].code]
                if cmp_feat_re.search(k_op_str):
                    cmp_feat = True
                    break
            
            if cmp_feat:
                ans.append((i, j))
    
    return ans

find_if_pairs.inst_range = 6




def select_unvisit(clone_pairs:list[tuple[int, int]], visitpath:str) -> list[tuple[int, int]]:
    ans = []

    visitfile = open(visitpath, "r")
    visit = json.load(visitfile)
    for pair in clone_pairs:
        if not list(pair) in visit:
            ans.append(pair)
    
    visitfile.close()
    return ans


def save_visit(clone_pairs:list[tuple[int, int]], visitpath:str):
    visitfile = open(visitpath, "w")
    json.dump(clone_pairs, visitfile)
    visitfile.close()

def iswrite(opaccess:OpAccess):
    return opaccess == OpAccess.WRITE or opaccess == OpAccess.COND_WRITE or\
    opaccess == OpAccess.READ_WRITE or opaccess == OpAccess.READ_COND_WRITE

def isrelevant(reg:Register, regs:list):
    fullreg = RegisterExt.full_register(reg)
    return fullreg in list(map(RegisterExt.full_register, regs))

def select_valid_range(clone_pairs:list[tuple[int, int]], all_insts:list[Instruction]) -> list[tuple[int, int]]:
    ''' between 2 fetches
        1. no relevant register is overwritten
        2. no direct jump
    '''
    ans = []
    factory = InstructionInfoFactory()

    for i in range(len(clone_pairs)):
        pair = clone_pairs[i]
        insn0:Instruction = all_insts[pair[0]]

        regs = []
        if insn0.memory_base != Register.NONE:
            regs.append(insn0.memory_base)
        if insn0.memory_index != Register.NONE:
            regs.append(insn0.memory_index)
        
        fail = False
        for j in range(pair[0], pair[1]):
            ins:Instruction = all_insts[j]
            info:InstructionInfo = factory.info(ins)
            if code_to_str[ins.code].startswith("JMP") or code_to_str[ins.code].startswith("RET"):
                fail = True
                break
            
            for k in range(ins.op_count):
                if ins.op_kind(k) == OpKind.REGISTER and iswrite(info.op_access(k)) and isrelevant(ins.op_register(k), regs):
                    fail = True
                    break
            
            if fail:
                break
        if not fail:
            ans.append(pair)
    
    return ans


def select_line_check(all_insts:list[Instruction], pc_dPosMap:dict[int, tuple[str, int, int, str]], pairs:list[tuple[int, int]]) -> list[tuple[int, int]]:
    ans = []

    for i in range(len(pairs)):
        pair = pairs[i]
        insn0:Instruction = all_insts[pair[0]]
        insn1:Instruction = all_insts[pair[1]]
        if (not insn0.ip in pc_dPosMap) or (not insn1.ip in pc_dPosMap):
            continue
        file0, line0 = pc_dPosMap[insn0.ip][0], pc_dPosMap[insn0.ip][1]
        file1, line1 = pc_dPosMap[insn1.ip][0], pc_dPosMap[insn1.ip][1]

        if file0 == file1 and abs(line0 - line1) < 10:
            ans.append(pair)
    
    return ans


'''
For removed-clone check:
    filter pairs whose matched variables exist in the corresponding lines
'''
def select_no_match_vars(jsonPath:str, all_insts:list[Instruction], pc_dPosMap:dict[int, tuple[str, int, int, str]], pairs:list[tuple[int, int]]) -> list[tuple[int, int]]:
    ans = []
    mgr = VarMgr()
    if jsonPath != "":
        mgr.load(jsonPath)

    for i in range(len(pairs)):
        try:
            pair = pairs[i]
            print()
            print(f"processing {i} pair")
            insn0:Instruction = all_insts[pair[0]]
            insn1:Instruction = all_insts[pair[1]]

            names_from_dwarf = []
            
            firstip, secondip = insn0.ip, all_insts[pair[1]].ip
            addrExps, tmp = mgr.find(firstip), mgr.find(secondip)
            addrExps.intersection_update(tmp)
            print(f"need analyze {len(addrExps)} addrExps")
            src_ind, dst_ind = 1, 0
            if insn0.op_count == 1:
                src_ind, dst_ind = 0, 0

        
            for addrExp in addrExps:
                piece_name = f"/tmp/{firstip:X}_{secondip:X}_{addrExp.name}"
                startpc, endpc = addrExp.startpc, addrExp.endpc
                l, r = find_l_ind(all_insts, startpc), find_l_ind(all_insts, endpc)
                piece_asm, piece_addrs = construct(all_insts[l:r], startpc, endpc)
                with open(piece_name + ".S", "w") as piece_asm_file:
                    piece_asm_file.write(piece_asm)
                
                ret = os.system(f"as {piece_name}.S -o {piece_name}.o && ld {piece_name}.o -Ttext 0 -o {piece_name}")

                piece_file = open(piece_name, "rb")
                proj = angr.Project(piece_file, load_options={'auto_load_libs' : False})
                cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
                analysis:Analysis = Analysis(proj, cfg)
                analysis.analyzeCFG()

                reses = analysis.match(addrExp, DwarfType(addrExp.type), piece_addrs, True, False)

                for res in reses:
                    if res.addr == firstip:
                        if code_to_str[insn0.code].startswith("TEST") or code_to_str[insn0.code].startswith("CMP") or \
                        (isDestPos(res.matchPos) and insn0.op_kind(dst_ind) == OpKind.MEMORY) or \
                        (not isDestPos(res.matchPos) and insn0.op_kind(src_ind) == OpKind.MEMORY):
                            names_from_dwarf.append(addrExp.name)
                
                analysis.clear()

            line_content = ""
            # print(f"sed -n {pc_dPosMap[insn0.ip][1]}p {pc_dPosMap[insn0.ip][0]}")
            line0, line1 = pc_dPosMap[insn0.ip][1], pc_dPosMap[insn1.ip][1] if pc_dPosMap else -1
            file0, file1 = pc_dPosMap[insn0.ip][0], pc_dPosMap[insn1.ip][0] if pc_dPosMap else -1
            line_content += os.popen(f"sed -n {line0}p {file0}").read().strip()
            line_content += "   "
            line_content += os.popen(f"sed -n {line1}p {file1}").read().strip()
            
            noMatch = True
            # if len(names_from_dwarf) == 0:
            #     noMatch = False
            for name in names_from_dwarf:
                if name in line_content:
                    noMatch = False
                    break
            

            if noMatch:
                ans.append(pair)

            # if line0 == -1:
            #     preview_src = ""
            # else:
            #     preview_src = os.popen(f"sed -n {max(1, line0-7)},{line0}p {file0}").read().strip()
            #     preview_src += "\n---------------------------------------\n"
            #     preview_src += os.popen(f"sed -n {line0+1},{line1}p {file1}").read()
            #     preview_src += "\n"

            # if noMatch:
            #     ans.append(pair)
            #     if res_path != "":
            #         with open(res_path, "a") as res_file:
            #             res_file.write(preview_src)
            #             res_file.write(res_str(all_insts[pair[0]], all_insts[pair[1]], names_from_dwarf))
        except Exception:
            print(f"meet exception at {i}")
    
    return ans

def output_result(res_path:str, clone_pairs:list[tuple[int, int]], all_insts:list[Instruction], pc_dPosMap:dict[int, tuple[str, int, int, str]]):
    
    for pair in clone_pairs:

        if pc_dPosMap:
            insn0, insn1 = all_insts[pair[0]], all_insts[pair[1]]
            line0, line1 = pc_dPosMap[insn0.ip][1], pc_dPosMap[insn1.ip][1]
            file0, file1 = pc_dPosMap[insn0.ip][0], pc_dPosMap[insn1.ip][0]
            preview_src = os.popen(f"sed -n {max(1, line0-7)},{line0}p {file0}").read().strip()
            preview_src += "\n---------------------------------------\n"
            preview_src += os.popen(f"sed -n {line0+1},{line1}p {file1}").read()
            preview_src += "\n"
        
        else:
            preview_src = ""


        if res_path != "":
            with open(res_path, "a") as res_file:
                res_file.write(preview_src)
                res_file.write(res_str(all_insts[pair[0]], all_insts[pair[1]], []))
        
        else:
            print(preview_src)
            print(res_str(all_insts[pair[0]], all_insts[pair[1]], []))



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binPath")
    parser.add_argument("--jsonPath", "-jP", help="provide variable json file generated by extracter", default="")
    parser.add_argument("--check", "-c", help="specify the check pattern [clone|cmp]", default="clone")
    parser.add_argument("--line", "-l", action="store_true")
    parser.add_argument("--varviewer", "-v", action="store_true")
    parser.add_argument("--saveVisit", "-sV", default="")
    parser.add_argument("--useVisit", "-uV", default="")
    parser.add_argument("--output", "-o", help="specify result output path", default="")
    args:argparse.Namespace = parser.parse_args()
    

    check_pattern:str = args.check
    res_path = args.output
    file = open(args.binPath, "rb")
    elf = ELFFile(file)
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
        exit(1)
    formatter = Formatter(FormatterSyntax.GAS)
    all_insts = []
    for inst in decoder:
        all_insts.append(inst)
    
    file.close()


    ''' binary check part
    '''
    # get candidate instruction id pair
    if check_pattern == "clone":
        clone_pairs = find_clone_pair(all_insts)
    elif check_pattern == "cmp":
        clone_pairs = find_if_pairs(all_insts)
    else:
        print("please select the correct check pattern [clone|cmp]", file=sys.stderr)

    if args.useVisit != "":
        clone_pairs = select_unvisit(clone_pairs, args.useVisit)

    clone_pairs = select_valid_range(clone_pairs, all_insts)


    ''' debug info check part
    '''
    # get source line map
    #!!! only use when .raw file exists
    hasraw = os.path.exists(args.binPath + ".raw")
    pc_dPosMap = parse_Objdump(args.binPath, []) if hasraw else None

    # select pairs whose line near to each other
    if args.line and hasraw:
        clone_pairs = select_line_check(all_insts, pc_dPosMap, clone_pairs)

    # select pairs that match other variable
    if args.varviewer:
        clone_pairs = select_no_match_vars(args.jsonPath, all_insts, pc_dPosMap, clone_pairs)

    if args.saveVisit != "":
        save_visit(clone_pairs, args.saveVisit)


    # output match results
    output_result(args.output, clone_pairs, all_insts, pc_dPosMap)

    print(f"{len(clone_pairs)} in total")
