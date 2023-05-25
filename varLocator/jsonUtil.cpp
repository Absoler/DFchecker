#include "jsonUtil.h"
#include "Address.h"


json createJsonforExpression(const Expression &exp){
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
    json res;
    res["offset"] = exp.offset;
    json reg_array;
    for(int i=0; i<REG_END; ++i){
        if(exp.reg_scale[i]){
            reg_array.push_back({
                {"reg_ind", i}, 
                {"scale", exp.reg_scale[i]}
            });
        }
    }
    res["reg_scale"] = reg_array;
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
            "piece" : {
                "piece_start" : <Dwarf_Addr>,
                "piece_size" : <int>
            }
        }
    */
    json res = createJsonforExpression(addrexp);
    res["type"] = addrexp.type;
    res["startpc"] = addrexp.startpc;
    res["endpc"] = addrexp.endpc;
    res["reg"] = addrexp.reg;
    res["piece"] = {
        {"piece_start", addrexp.piece.first},
        {"piece_size", addrexp.piece.second}
    };
    
    

    return res;
}

json createJsonforAddress(const Address &addr){
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
    json res;
    for(AddressExp addrExp:addr.addrs){
        res["addrs"].push_back(createJsonforAddressExp(addrExp));
    }
    res["name"] = addr.name;
    res["valid"] = addr.valid;
    return res;
}