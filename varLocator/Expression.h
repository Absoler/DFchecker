#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#define REG_END 128
extern const char *reg_names[REG_END] ;

/*
    Expression is a symbolic simulation of dynamic calculation of Dwarf expression
*/
class Expression{
    public:
    bool valid = true;  // error when generating this
    bool empty = false; // optimized away by compiler

    Expression();
    Expression(Dwarf_Unsigned val_u);
    Expression(Dwarf_Signed val_s);
    static Expression createEmpty();
    
    bool equal(const Expression& other);
    static bool valid_bin_op(const Expression& exp1, const Expression& exp2, Dwarf_Small op);
    static Expression bin_op(const Expression& exp1, const Expression& exp2, Dwarf_Small op);
    static bool valid_unary_op(const Expression& exp, Dwarf_Small op);
    static Expression unary_op(const Expression& exp, Dwarf_Small op);


    /*
        the value of `Expression` is val + reg0 * reg_scale[0] + reg1 * ...
    */
    Dwarf_Signed reg_scale[REG_END];
    Dwarf_Unsigned val;
    
    bool sign = false;
    bool no_reg() const;

    void reset();
    void output();
    void setExpFrom(const Expression &);
};