#pragma once

#include "Expression.h"
#include "Address.h"
class Address;
class AddressExp;


/*
    {
        "addrs" : [
            <AddressExp>
        ]
        "name" : <string>
        "piece_num" : <int>
        "valid" : <bool>
    }
*/

json createJsonforAddress(const Address& addr);


/*
    {
        Expression part ...

        "type" : <int>
        "startpc" : <Dwarf_Addr>
        "endpc" : <Dwarf_Addr>
        "reg" : <Dwarf_Half>
        "piece" : {
            "piece_start" : <Dwarf_Addr>,
            "piece_size" : <int>
        }
    }
*/
json createJsonforAddressExp(const AddressExp& addrexp);

/*
    {
        "offset" : <Dwarf_Unsigned>
        "regs" : [
            {
                "reg_ind" : <int>,
                "scale" : <int>
            }
        ]
        "valid" : <bool>
        "empty" : <bool>
    }
*/
json createJsonforExpression(const Expression& exp);