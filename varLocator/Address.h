#pragma once

#include "Expression.h"
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <string>
#include <vector>

enum AddrType{
    MEMORY,
    REGISTER,
    CONSTANT
};

// <piece_start, piece_size>
typedef std::pair<Dwarf_Addr, int> piece_type;


class AddressExp : public Expression{
    public:
    AddressExp() = default;
    AddressExp(AddrType _type);
    void reset();
    piece_type piece;

    AddrType type;
 
    // valid if type == REGISTER
    Dwarf_Half reg;

    // valid if type == CONSTANT
    Expression const_val;

    Dwarf_Addr startpc, endpc;  // not realize more complex range

    void output();
};

/*
    `Address` record address info of some lifetimes of a variable
*/
class Address{

    public:
    Address() = default;
    Address(AddrType _type);

    bool valid = false;
    
    
    std::string name;
    
    std::vector<AddressExp> addrs;
    int piece_num = 0;

    
    void output();
    void update_valid();
};
