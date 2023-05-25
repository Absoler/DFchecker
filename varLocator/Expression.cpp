#include "Expression.h"
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <libdwarf-0/libdwarf.h>

Expression Expression::createEmpty(){
    Expression res;
    res.empty = true;
    return res;
}

Expression::Expression(){
    memset(reg_scale, 0, sizeof(reg_scale));
    offset = 0;
    valid = true;
}

Expression::Expression(Dwarf_Unsigned _val_u){
    memset(reg_scale, 0, sizeof(reg_scale));
    offset = _val_u;
    valid = true;
}

Expression::Expression(Dwarf_Signed _val_s){
    memset(reg_scale, 0, sizeof(reg_scale));
    offset = (Dwarf_Unsigned)_val_s;
    valid = true;
}

bool Expression::equal(const Expression &other){
    bool res = offset == other.offset;
    for(int i=0; i<REG_END; ++i){
        if(reg_scale[i]!=other.reg_scale[i]){
            res = false;
            break;
        }
    }
    return res;
}

bool Expression::no_reg() const{
    for(int i=0; i<REG_END; ++i){
        if(reg_scale[i]) return false;
    }
    return true;
}

bool Expression::valid_bin_op(const Expression &exp1, const Expression &exp2, Dwarf_Small op){
    bool res = true;
    if(op == DW_OP_plus){
        
        
    }else if(op==DW_OP_div){
        res = exp1.no_reg();
        res &= (exp1.offset != 0);

    }else if(op==DW_OP_minus){

     
    }else if(op==DW_OP_mod){
        res = exp1.no_reg();
        res &= (exp1.offset != 0);
       
    }else if(op==DW_OP_mul){
        res = exp1.no_reg() || exp2.no_reg();
        
        
    }else if(op==DW_OP_or){
        res = exp1.no_reg() && exp2.no_reg();

    }else if(op==DW_OP_and){
        res = exp1.no_reg() && exp2.no_reg();

    }else if(op==DW_OP_shl){
        res = exp1.no_reg() && exp2.no_reg();

    }else if(op==DW_OP_shr){

        res = exp1.no_reg() && exp2.no_reg();
    }else if(op==DW_OP_shra){

        res = exp1.no_reg() && exp2.no_reg();
    }else if(op>=DW_OP_eq && op<=DW_OP_ne){
        res = exp1.no_reg() && exp2.no_reg();
    }

    return res;
}

Expression Expression::bin_op(const Expression &exp1, const Expression &exp2, Dwarf_Small op){
    /*
        binary operation of two expression
    */
    
    Expression res = exp1;

    if(!valid_bin_op(exp1, exp2, op)){
        res.valid = false;
        return res;
    }
    if(op == DW_OP_plus){
        
        res.offset += exp2.offset;
        for(int i=0; i<REG_END; ++i){
            res.reg_scale[i] += exp2.reg_scale[i];
        }
        
    }else if(op==DW_OP_div){
        
        Dwarf_Signed divisor = (Dwarf_Signed)res.offset;

        res.offset = (Dwarf_Signed)exp2.offset / divisor ; 
        for(int i=0; i<REG_END; ++i){
            res.reg_scale[i] = (Dwarf_Signed)exp2.reg_scale[i] / divisor;
        }
    }else if(op==DW_OP_minus){

        res.offset -= exp2.offset;
        for(int i=0; i<REG_END; ++i){
            res.reg_scale[i] -= exp2.reg_scale[i];
        }
    }else if(op==DW_OP_mod){

        for(int i=0; i<REG_END; ++i){
            res.reg_scale[i] = exp2.reg_scale[i] % res.offset;
        }
        res.offset = exp2.offset % res.offset;

    }else if(op==DW_OP_mul){

        if(res.no_reg()){
            for (int i=0; i<REG_END; ++i) {
                res.reg_scale[i] = res.offset * exp2.reg_scale[i];       
            }
        }else{
            for (int i=0; i<REG_END; ++i) {
                res.reg_scale[i] = exp2.offset * res.reg_scale[i];       
            }
        }
        res.offset = res.offset * exp2.offset;
        
    }else if(op==DW_OP_or){

        // must no reg
        res.offset |= exp2.offset;
    }else if(op==DW_OP_and){

        res.offset &= exp2.offset;
    }else if(op==DW_OP_shl){

        res.offset = exp2.offset << res.offset;
    }else if(op==DW_OP_shr){

        res.offset = exp2.offset >> res.offset;
    }else if(op==DW_OP_shra){

        res.offset = (Dwarf_Signed)exp2.offset >> res.offset;
    }else if(op==DW_OP_xor){

        res.offset ^= exp2.offset;
    }else if(op==DW_OP_eq){

        res.offset = (res.offset==exp2.offset?1:0);
    }else if(op==DW_OP_ge){
        
        res.offset = (exp2.offset>=res.offset?1:0);
    }else if(op==DW_OP_gt){
        
        res.offset = (exp2.offset>res.offset?1:0);
    }else if(op==DW_OP_le){
        
        res.offset = (exp2.offset<=res.offset?1:0);
    }else if(op==DW_OP_lt){
        
        res.offset = (exp2.offset<res.offset);
    }else if(op==DW_OP_ne){

        res.offset = (exp2.offset!=res.offset?1:0);
    }

    return res;
}

Expression Expression::unary_op(const Expression &exp, Dwarf_Small op){

    Expression res = exp;
    if(!valid_unary_op(exp, op)){
        res.valid = false;
        return res;
    }

    if (op==DW_OP_neg) {
        res.offset = -((Dwarf_Signed)res.offset);
        for(int i=0; i<REG_END; ++i){
            res.reg_scale[i] = -res.reg_scale[i];
        }
    }else if(op==DW_OP_abs){
        res.offset = std::abs((Dwarf_Signed)res.offset);
    }else if(op==DW_OP_not){
        res.offset = ~res.offset;
    }

    return res;
}

bool Expression::valid_unary_op(const Expression &exp, Dwarf_Small op){

    bool res = true;
    if(op==DW_OP_neg){

    }else if(op==DW_OP_abs){
        res = exp.no_reg();
    }else if(op==DW_OP_not){
        res = exp.no_reg();
    }

    return res;
}

void Expression::reset(){
    valid = true;
    memset(reg_scale, 0, sizeof(reg_scale));
    offset = 0;
}

void Expression::output(){
    printf("%llx", offset);
    for(int i=0; i<REG_END; ++i){
        if(reg_scale[i]){
            printf(" + %lld * %s", reg_scale[i], reg_names[i]);
        }
    }
    printf("\n");
}

void Expression::setExpFrom(const Expression &exp){
    empty = exp.empty;
    valid = exp.valid;
    memcpy(reg_scale, exp.reg_scale, sizeof(reg_scale));
    offset = exp.offset;
}

const char *reg_names[REG_END] = {
    "rax",
    "rdx",
    "rcx",
    "rbx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "RA",
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
    "xmm8",
    "xmm9",
    "xmm10",
    "xmm11",
    "xmm12",
    "xmm13",
    "xmm14",
    "xmm15",
    "st0",
    "st1",
    "st2",
    "st3",
    "st4",
    "st5",
    "st6",
    "st7",
    "mm0",
    "mm1",
    "mm2",
    "mm3",
    "mm4",
    "mm5",
    "mm6",
    "mm7",
    "rFLAGS",
    "es",
    "cs",
    "ss",
    "ds",
    "fs",
    "gs"
};