#include "Evaluator.h"
#include "Address.h"
#include "Expression.h"
#include <cassert>
#include <cstdio>
#include <libdwarf-0/libdwarf.h>
#include <stack>

#define no_handle(x) case x:\
    ret = x; \
    break;

int Evaluator::init_stack(){
    while(!stk.empty()){
        stk.pop();
    }
    return 0;
}

int Evaluator::exec_operation(Dwarf_Small op, Dwarf_Unsigned op1, Dwarf_Unsigned op2, Dwarf_Unsigned op3){
    /*
        retval indicates the operation an error happened in
    */
    int ret = 0;
    switch (op) {
    case DW_OP_addr:
        stk.push(std::move(Expression(op1)));
        break;
    case DW_OP_deref:
        ret = DW_OP_deref;
        break;
    case DW_OP_const1u:
    case DW_OP_const2u:
    case DW_OP_const4u:
    case DW_OP_const8u:
    case DW_OP_constu:
        stk.push(std::move(Expression(op1)));
        break;
    case DW_OP_const1s:
    case DW_OP_const2s:
    case DW_OP_const4s:
    case DW_OP_const8s:
    case DW_OP_consts:
        stk.push(std::move(Expression((Dwarf_Signed)op1)));
        break;
    case DW_OP_dup:
        stk.push(stk.top());
        break;
    case DW_OP_drop:
        stk.pop();
        break;
    case DW_OP_over:
        ret = DW_OP_over;
        break;
    case DW_OP_pick:
        ret = DW_OP_pick;
        break;
    case DW_OP_swap:
        {
            Expression first = stk.top();
            stk.pop();
            Expression second = stk.top();
            stk.pop();
            stk.push(first);
            stk.push(second);
        }
    case DW_OP_rot:
        {
            Expression first = stk.top();
            stk.pop();
            Expression second = stk.top();
            stk.pop();
            Expression third = stk.top();
            stk.pop();
            stk.push(first);
            stk.push(third);
            stk.push(second);
        }
    no_handle(DW_OP_xderef)
    
    
    case DW_OP_and:
    case DW_OP_div:
    case DW_OP_minus:
    case DW_OP_mod:
    case DW_OP_mul:
    case DW_OP_or:
    case DW_OP_plus:
    case DW_OP_shl:
    case DW_OP_shr:
    case DW_OP_shra:
    case DW_OP_xor:
    case DW_OP_eq:
    case DW_OP_ge:
    case DW_OP_gt:
    case DW_OP_le:
    case DW_OP_lt:
    case DW_OP_ne:
    {
        Expression exp1 = stk.top();
        stk.pop();
        Expression exp2 = stk.top();
        stk.pop();
        Expression res = Expression::bin_op(exp1, exp2, op);
        if(!res.valid){
            ret = op;
        }else{
            stk.push(res);
        }
        break;
    }

    case DW_OP_abs:
    case DW_OP_neg:
    case DW_OP_not:
    {
        Expression exp = stk.top();
        stk.pop();
        Expression res = Expression::unary_op(exp, op);
        if(!res.valid){
            ret = op;
        }else{
            stk.push(res);
        }
        break;
    }

    no_handle(DW_OP_bra)
    no_handle(DW_OP_skip)

    case DW_OP_lit0:
    case DW_OP_lit1:
    case DW_OP_lit2:
    case DW_OP_lit3:
    case DW_OP_lit4:
    case DW_OP_lit5:
    case DW_OP_lit6:
    case DW_OP_lit7:
    case DW_OP_lit8:
    case DW_OP_lit9:
    case DW_OP_lit10:
    case DW_OP_lit11:
    case DW_OP_lit12:
    case DW_OP_lit13:
    case DW_OP_lit14:
    case DW_OP_lit15:
    case DW_OP_lit16:
    case DW_OP_lit17:
    case DW_OP_lit18:
    case DW_OP_lit19:
    case DW_OP_lit20:
    case DW_OP_lit21:
    case DW_OP_lit22:
    case DW_OP_lit23:
    case DW_OP_lit24:
    case DW_OP_lit25:
    case DW_OP_lit26:
    case DW_OP_lit27:
    case DW_OP_lit28:
    case DW_OP_lit29:
    case DW_OP_lit30:
    case DW_OP_lit31:
        stk.push(std::move(Expression((Dwarf_Unsigned)op-DW_OP_lit0)));
        break;
    
    case DW_OP_breg0:
    case DW_OP_breg1:
    case DW_OP_breg2:
    case DW_OP_breg3:
    case DW_OP_breg4:
    case DW_OP_breg5:
    case DW_OP_breg6:
    case DW_OP_breg7:
    case DW_OP_breg8:
    case DW_OP_breg9:
    case DW_OP_breg10:
    case DW_OP_breg11:
    case DW_OP_breg12:
    case DW_OP_breg13:
    case DW_OP_breg14:
    case DW_OP_breg15:
    case DW_OP_breg16:
    case DW_OP_breg17:
    case DW_OP_breg18:
    case DW_OP_breg19:
    case DW_OP_breg20:
    case DW_OP_breg21:
    case DW_OP_breg22:
    case DW_OP_breg23:
    case DW_OP_breg24:
    case DW_OP_breg25:
    case DW_OP_breg26:
    case DW_OP_breg27:
    case DW_OP_breg28:
    case DW_OP_breg29:
    case DW_OP_breg30:
    case DW_OP_breg31:
    {
        Expression reg_off;
        reg_off.reg_scale[op-DW_OP_breg0] = 1;
        reg_off.val = op1;
        stk.push(reg_off);
        break;
    }

    no_handle(DW_OP_regx)
    no_handle(DW_OP_fbreg)

    case DW_OP_bregx:
    {
        Expression reg_off;
        reg_off.reg_scale[op1] = 1;
        reg_off.val = op2;
        stk.push(reg_off);
        break;
    }

    // handle this outside
    no_handle(DW_OP_piece)
    no_handle(DW_OP_bit_piece)

    no_handle(DW_OP_deref_size)
    no_handle(DW_OP_xderef_size)
    
    no_handle(DW_OP_nop)

    // has version 3 or 4 label, thought unsupported now wrongly..
    no_handle(DW_OP_push_object_address)
    no_handle(DW_OP_call2)
    no_handle(DW_OP_call4)
    no_handle(DW_OP_call_ref)
    no_handle(DW_OP_form_tls_address)
    no_handle(DW_OP_call_frame_cfa)
    no_handle(DW_OP_implicit_pointer)


    // retrieve from .debug_addr
    no_handle(DW_OP_addrx)
    no_handle(DW_OP_constx)

    // get another expression from op2, problem
    no_handle(DW_OP_entry_value)
    
    no_handle(DW_OP_const_type)
    no_handle(DW_OP_regval_type)
    no_handle(DW_OP_deref_type)
    no_handle(DW_OP_xderef_type)

    case DW_OP_convert:
        /*
            1. get an DW_AT_base_type die (with dwarf_offdie_b()) 
            2. cast stk.top() to it, need parse a type die
        */
        break;

    case DW_OP_reinterpret:
        /*
            reinterpret the bits
        */
        break;
    }
        
    return ret;
}

Address Evaluator::read_location(Dwarf_Attribute loc_attr, Dwarf_Half loc_form){
    /*
        only parse DW_FORM_sec_offset and DW_FORM_exprloc now
    */
    int ret;
    Address res;
    Dwarf_Error err;
    Dwarf_Loc_Head_c loclist_head;
    Dwarf_Unsigned locentry_len;
    if(loc_form!=DW_FORM_sec_offset&&
        loc_form!=DW_FORM_exprloc&&
        loc_form!=DW_FORM_block&&
        loc_form!=DW_FORM_data1&&loc_form!=DW_FORM_data2&&loc_form!=DW_FORM_data4&&loc_form!=DW_FORM_data8)
        res.valid = false;
    else
        ret = dwarf_get_loclist_c(loc_attr, &loclist_head, &locentry_len, &err);
    
    if(ret!=DW_DLV_OK){
        res.valid = false;
        return res;
    }

    for(Dwarf_Unsigned i = 0; i<locentry_len; i++){
        Dwarf_Small lkind=0, lle_value=0;
        Dwarf_Unsigned raw_lopc=0, raw_hipc=0;
        Dwarf_Bool debug_addr_unavailable = false;
        Dwarf_Addr lopc = 0;
        Dwarf_Addr hipc = 0;
        Dwarf_Unsigned loclist_expr_op_count = 0;
        Dwarf_Locdesc_c locdesc_entry = 0;
        Dwarf_Unsigned expression_offset = 0;
        Dwarf_Unsigned locdesc_offset = 0;

        ret = dwarf_get_locdesc_entry_d(loclist_head, i,
        &lle_value,
        &raw_lopc, &raw_hipc,
        &debug_addr_unavailable,
        &lopc,&hipc,
        &loclist_expr_op_count,
        &locdesc_entry,
        &lkind,
        &expression_offset,
        &locdesc_offset,
        &err);

        if(ret!=DW_DLV_OK){
            res.valid = false;
            return res;
        }

        AddressExp addr;
        init_stack();

        if(!debug_addr_unavailable){
            addr.startpc = lopc;
            addr.endpc = hipc;
        }else{
            addr.startpc = raw_lopc;
            addr.endpc = raw_hipc;
        }

        Dwarf_Small op = 0;
        Dwarf_Unsigned piece_base = 0;
        bool no_end = true;
        
        for(Dwarf_Unsigned j = 0; j<loclist_expr_op_count; j++){
            Dwarf_Unsigned op1, op2, op3, offsetForBranch;
            

            ret = dwarf_get_location_op_value_c(locdesc_entry, j, &op, &op1, &op2, &op3, &offsetForBranch, &err);
            if(ret != DW_DLV_OK){
                
            }

            if((op>=DW_OP_reg0&&op<=DW_OP_reg31) || op==DW_OP_regx){
                // reg addressing
                addr.type = REGISTER;
                addr.reg = (op==DW_OP_regx? op1 : op-DW_OP_reg0);

                no_end = false;
            }
            else if(op==DW_OP_implicit_value || op==DW_OP_stack_value){
                // immediate addressing
                addr.type = CONSTANT;
                if(op==DW_OP_implicit_value){
                    if(op1>8){
                        // how to deal with LEB128 coding with size > 8?
                    }

                    addr.const_val = Expression(op2);
                    
                }else if(op==DW_OP_stack_value){

                    addr.const_val = stk.top();

                }
                no_end = false;
            }else if(op==DW_OP_piece){

                // deal with piece case
                addr.piece = std::pair<Dwarf_Unsigned, int>(piece_base, op1);
                if(addr.type == MEMORY){
                    if(stk.empty()){
                        addr.setExpFrom(Expression::createEmpty());
                    }else{
                        addr.setExpFrom(stk.top());
                    }
                }
                res.addrs.push_back(addr);
                addr.reset();
                no_end = false;
            }else{

                // indirect addressing
                ret = exec_operation(op, op1, op2, op3);
                if(ret!=0){
                    const char *op_name;
                    dwarf_get_OP_name(op, &op_name);
                    fprintf(stderr, "parse expression wrong at %s", op_name);
                    addr.valid = false;
                    break;
                }
                no_end = true;

            }
            
        }

        if(no_end){
            if(stk.empty()){
                addr.setExpFrom(Expression::createEmpty());
            }else{
                addr.setExpFrom(stk.top());
            }
        }

        res.addrs.push_back(addr);


    }
    res.update_valid();
    
    return res;
}