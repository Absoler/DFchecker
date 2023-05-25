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
}


void AddressExp::output(){
    printf("%llx %llx\n", startpc, endpc);
    printf("%u\n", type);
    if(type==MEMORY){
        Expression::output();
    }else if(type==REGISTER){

        printf("%s\n", reg_names[reg]);
    }else{
        Expression::output();
    }
}

void Address::output(){
    printf("\n");
    printf("address %s\n", name.c_str());
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