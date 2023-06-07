#include "jsonUtil.h"
#include "Address.h"
#include <map>
#include <string>

json createJsonforExpression(const Expression &exp){
    /*
        {
            "offset" : <Dwarf_Unsigned>
            "regs" : {
                <int>(reg_ind) : <int>(scale),
            }
            "valid" : <bool>
            "empty" : <bool>
        }
    */
    json res;
    res["offset"] = exp.offset;
    

    json reg_dict;
    for(int i=0; i<REG_END; ++i){
        if(exp.reg_scale[i]){
            reg_dict[std::to_string(i)] = exp.reg_scale[i];
            // reg_dict[i] = exp.reg_scale[i];
        }
    }
    res["regs"] = reg_dict;
    res["valid"] = exp.valid;
    res["empty"] = exp.empty;

    return res;
}

json createJsonforAddressExp(const AddressExp &addrexp){
    /*
        {
            Expression part ...

            "type" : <int>
            "startpc" : <Dwarf_Addr>
            "endpc" : <Dwarf_Addr>
            "reg" : <Dwarf_Half>
            "piece_start" : <Dwarf_Addr>,
            "piece_size" : <int>
        }
    */
    json res = createJsonforExpression(addrexp);
    res["type"] = addrexp.type;
    res["startpc"] = addrexp.startpc;
    res["endpc"] = addrexp.endpc;
    res["reg"] = addrexp.reg;
    res["piece_start"] = addrexp.piece.first;
    res["piece_size"] = addrexp.piece.second;
    
    

    return res;
}

json createJsonforAddress(const Address &addr){
    /*
        {
            "addrExps" : [
                <AddressExp>
            ]
            "name" : <string>
            "decl_file" : <string>
            "decl_row"  : <Dwarf_Unsigned>
            "decl_col"  : <Dwarf_Unsigned>
            "piece_num" : <int>
            "valid" : <bool>
        }
    */
    json res;
    for(AddressExp addrExp:addr.addrs){
        res["addrExps"].push_back(createJsonforAddressExp(addrExp));
    }
    res["name"] = addr.name;
    res["decl_file"] = addr.decl_file;
    res["decl_row"] = addr.decl_row;
    res["decl_col"] = addr.decl_col;
    res["valid"] = addr.valid;

    return res;
}