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

res_path:str = ""

def res_str(inst_i:Instruction, inst_j:Instruction, names:list = []):
    return f"{inst_i.ip:X}: {formatter.format(inst_i)}\n" +\
           f"{inst_j.ip:X}: {formatter.format(inst_j)}\n" +\
           f"{names}\n\n\n"

check_re = re.compile(r'CMP|SUB|TEST|AND|SHL|SAL|ROL|DEC')
def is_check_memory(i:int, insts:list[Instruction]) -> bool:
    
    inst:Instruction = insts[i]
    if inst.code not in code_to_str:
        return False
    
    code_str:str = code_to_str[inst.code]

    # has memory operation
    if not hasMem(inst):
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

def is_use_memory(inst:Instruction):

    if not hasMem(inst):
        return False
    
    code_str:str = code_to_str[inst.code]
    if code_str.startswith("CMP") or\
        code_str.startswith("TEST") or\
        code_str.startswith("CMOV"):
        return False
    
    return inst.op1_kind == OpKind.MEMORY


def find_clone_pair(insts:list[Instruction]) -> list[tuple[int, int]]:
    ''' constraints:
        1. a variable loaded in two instructions inside a range
            1. test, cmp..
            2. any load
        
        2. mapped variable name doesn't occur in mapped lines
    '''
    inst_range = 5

    factory = InstructionInfoFactory()
    ans = []

    # constraint 1
    for i in range(len(insts)):
        ''' first must be check instruction such as cmp or test
        '''
        if not is_check_memory(i, insts):
            continue

        for j in range(i+1, i+inst_range+1):
            if not is_use_memory(insts[j]):
                continue

            if not sameMem(insts[i], insts[j]):
                continue

            
            ans.append((i, j))


    return ans

def select_line_check(all_insts:list[Instruction], pc_dPosMap:dict[int, tuple[str, int, int, str]], pairs:list[tuple[int, int]]):
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


def select_match_vars(jsonPath:str, all_insts:list[Instruction], pc_dPosMap:dict[int, tuple[str, int, int, str]], pairs:list[tuple[int, int]]) -> list[set[AddressExp]]:
    ans = []
    mgr = VarMgr()
    mgr.load(jsonPath)

    for i in range(len(pairs)):
        try:
            pair = pairs[i]
            print()
            print(f"processing {i} pair")
            insn0:Instruction = all_insts[pair[0]]
            insn1:Instruction = all_insts[pair[1]]
            firstip, secondip = insn0.ip, all_insts[pair[1]].ip
            addrExps, tmp = mgr.find(firstip), mgr.find(secondip)
            addrExps.intersection_update(tmp)
            print(f"need analyze {len(addrExps)} addrExps")
            src_ind, dst_ind = 1, 0
            if insn0.op_count == 1:
                src_ind, dst_ind = 0, 0

            names_from_dwarf = []
            # for addrExp in addrExps:
            #     piece_name = f"/tmp/{firstip:X}_{secondip:X}_{addrExp.name}"
            #     startpc, endpc = addrExp.startpc, addrExp.endpc
            #     l, r = find_l_ind(all_insts, startpc), find_l_ind(all_insts, endpc)
            #     piece_asm, piece_addrs = construct(all_insts[l:r], startpc, endpc)
            #     with open(piece_name + ".S", "w") as piece_asm_file:
            #         piece_asm_file.write(piece_asm)
                
            #     ret = os.system(f"as {piece_name}.S -o {piece_name}.o && ld {piece_name}.o -Ttext 0 -o {piece_name}")

            #     piece_file = open(piece_name, "rb")
            #     proj = angr.Project(piece_file, load_options={'auto_load_libs' : False})
            #     cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
            #     analysis:Analysis = Analysis(proj, cfg)
            #     analysis.analyzeCFG()

            #     reses = analysis.match(addrExp, DwarfType(addrExp.type), piece_addrs, True, False)

            #     for res in reses:
            #         if res.addr == firstip:
            #             if code_to_str[insn0.code].startswith("TEST") or code_to_str[insn0.code].startswith("CMP") or \
            #             (isDestPos(res.matchPos) and insn0.op_kind(dst_ind) == OpKind.MEMORY) or \
            #             (not isDestPos(res.matchPos) and insn0.op_kind(src_ind) == OpKind.MEMORY):
            #                 names_from_dwarf.append(addrExp.name)
                
            #     analysis.clear()

            line_content = ""
            # print(f"sed -n {pc_dPosMap[insn0.ip][1]}p {pc_dPosMap[insn0.ip][0]}")
            line0, line1 = pc_dPosMap[insn0.ip][1], pc_dPosMap[insn1.ip][1]
            file0, file1 = pc_dPosMap[insn0.ip][0], pc_dPosMap[insn1.ip][0]
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

            preview_src = os.popen(f"sed -n {max(1, line0-7)},{line0}p {file0}").read().strip()
            preview_src += "\n---------------------------------------\n"
            preview_src += os.popen(f"sed -n {line0+1},{line1}p {file1}").read()
            preview_src += "\n"

            if noMatch:
                ans.append(pair)
                if res_path != "":
                    with open(res_path, "a") as res_file:
                        res_file.write(preview_src)
                        res_file.write(res_str(all_insts[pair[0]], all_insts[pair[1]], names_from_dwarf))
        except Exception:
            print(f"meet exception at {i}")
    
    return ans




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binPath")
    parser.add_argument("jsonPath")
    parser.add_argument("--clone", "-c", action="store_true")
    parser.add_argument("--line", "-l", action="store_true")
    parser.add_argument("--show", "-s", help="print instruction code meanwhile", action="store_true")
    parser.add_argument("--output", "-o", help="specify result output path", default="")
    args:argparse.Namespace = parser.parse_args()
    
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
    
    # get candidate instruction id pair
    clone_pairs = find_clone_pair(all_insts)

    # get source line map
    pc_dPosMap = parse_Objdump(args.binPath, [])

    # select pairs whose line near to each other
    if args.line:
        clone_pairs = select_line_check(all_insts, pc_dPosMap, clone_pairs)

    # select pairs that match other variable
    if args.clone:
        clone_pairs = select_match_vars(args.jsonPath, all_insts, pc_dPosMap, clone_pairs)

    print(f"{len(clone_pairs)} in total")
    if res_path == "":
        for pair in clone_pairs:
            inst_i, inst_j = all_insts[pair[0]], all_insts[pair[1]]
            if args.show:
                print(res_str(inst_i, inst_j))
            else:
                print(f"{inst_i.ip:X} {inst_j.ip:X}")
