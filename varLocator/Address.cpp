#include "Address.h"
#include "Expression.h"
#include <cstdio>
#include <libdwarf-0/libdwarf.h>

AddressExp::AddressExp(AddrType _type){
    type = _type;
}

void AddressExp::reset(){
    Expression::reset();
    type = MEMORY;
    reg = REG_END;
    const_val = Expression();
}


void AddressExp::output(){
    printf("%llx %llx\n", startpc, endpc);
    printf("%u\n", type);
    if(type==MEMORY){
        Expression::output();
    }else if(type==REGISTER){
        const char* reg_name;
        dwarf_get_FRAME_name(reg, &reg_name);

        printf("%s\n", reg_name);
    }else{
        const_val.output();
    }
}

void Address::output(){
    printf("\n");
    printf("%s\n", name.c_str());
    for(AddressExp addr: addrs){
        addr.output();
    }
}

void Address::update_valid(){
    valid = true;
    for(AddressExp &addr: addrs){
        if(!addr.valid){
            valid = false;
            break;
        }
    }
}