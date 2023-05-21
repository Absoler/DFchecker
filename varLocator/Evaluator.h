#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include "Address.h"
#include <stack>

class Evaluator{
    static const int mx_stack = 1000;
    std::stack<Expression> stk;
    
    public:
    int init_stack();

    int exec_operation(Dwarf_Small op, Dwarf_Unsigned op1, Dwarf_Unsigned op2, Dwarf_Unsigned op3);

    Address read_location(Dwarf_Attribute loc_attr, Dwarf_Half loc_form);

};