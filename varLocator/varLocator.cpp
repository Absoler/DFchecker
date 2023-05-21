#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include "Address.h"
#include "Evaluator.h"

#define simple_handle_err(res) do{ \
    if(res!=DW_DLV_OK){ \
        return res; \
    } \
}while(0);
inline void printindent(int indent){
    for(int _=0;_<indent;++_)
        printf("\t");
}

int get_name(Dwarf_Debug dbg, Dwarf_Die die, char **name){
    Dwarf_Error err;
    int ret = 0, res;
    Dwarf_Bool has_name = false, has_origin = false;
    res = dwarf_hasattr(die, DW_AT_name, &has_name, &err);
    res = dwarf_hasattr(die, DW_AT_abstract_origin, &has_origin, &err);
    simple_handle_err(res)
    if(has_name){
        Dwarf_Attribute name_attr;
        Dwarf_Half name_form;
        dwarf_attr(die, DW_AT_name, &name_attr, &err);
        if(res == DW_DLV_OK){
            dwarf_whatform(name_attr, &name_form, &err);
            if(name_form==DW_FORM_string||name_form==DW_FORM_line_strp||name_form==DW_FORM_strp){
                res = dwarf_formstring(name_attr, name, &err);
                return res;
            }
        }
    }else if(has_origin){
        Dwarf_Attribute off_attr;
        Dwarf_Half off_form;
        res = dwarf_attr(die, DW_AT_abstract_origin, &off_attr, &err);
        simple_handle_err(res)

        res = dwarf_whatform(off_attr, &off_form, &err);
        if(res!=DW_DLV_OK){
            dwarf_dealloc_attribute(off_attr);
            return 1;
        }

        Dwarf_Off offset;
        Dwarf_Bool is_info;
        res = dwarf_global_formref_b(off_attr, &offset, &is_info, &err);

        if(res!=DW_DLV_OK){
            dwarf_dealloc_attribute(off_attr);
            return 1;
        }

        Dwarf_Die origin_die;
        res = dwarf_offdie_b(dbg, offset, is_info, &origin_die, &err);

        Dwarf_Attribute name_attr;
        Dwarf_Half name_form;
        dwarf_attr(origin_die, DW_AT_name, &name_attr, &err);
        if(res == DW_DLV_OK){
            dwarf_whatform(name_attr, &name_form, &err);
            if(name_form==DW_FORM_string||name_form==DW_FORM_line_strp||name_form==DW_FORM_strp){
                res = dwarf_formstring(name_attr, name, &err);
                return res;
            }
        }
    }
    return ret;
}

int test_evaluator(Dwarf_Debug dbg, Dwarf_Die var_die){
    int res;
    Dwarf_Error err;
    Dwarf_Attribute location_attr;
    res = dwarf_attr(var_die, DW_AT_location, &location_attr, &err);
    simple_handle_err(res)
    Dwarf_Half loc_form;
    res = dwarf_whatform(location_attr, &loc_form, &err);
    simple_handle_err(res)

    Evaluator evaluator;
    Address addr = evaluator.read_location(location_attr, loc_form);
    if(addr.valid == false){
        return 1;
    }
    char *name = NULL;
    res = get_name(dbg, var_die, &name);
    simple_handle_err(res)
    addr.name = std::string(name);
    addr.output();
    return 0;
}

int processLocation(Dwarf_Attribute loc_attr, Dwarf_Half loc_form, int indent){
    int ret = 0;
    int res = 0;
    Dwarf_Error err;
    Dwarf_Loc_Head_c loclist_head;
    Dwarf_Unsigned locentry_len;
    if(loc_form!=DW_FORM_sec_offset&&
        loc_form!=DW_FORM_exprloc&&
        loc_form!=DW_FORM_block&&
        loc_form!=DW_FORM_data1&&loc_form!=DW_FORM_data2&&loc_form!=DW_FORM_data4&&loc_form!=DW_FORM_data8)
        res = 1;
    else
        res = dwarf_get_loclist_c(loc_attr, &loclist_head, &locentry_len, &err);
    printf(" %s", (res==DW_DLV_OK?" get success! ":" fail "));
    if(res==DW_DLV_OK){
        for(Dwarf_Unsigned i = 0; i<locentry_len; i++){
            Dwarf_Small lkind=0, lle_value=0;
            Dwarf_Unsigned rawval1=0, rawval2=0;
            Dwarf_Bool debug_addr_unavailable = false;
            Dwarf_Addr lopc = 0;
            Dwarf_Addr hipc = 0;
            Dwarf_Unsigned loclist_expr_op_count = 0;
            Dwarf_Locdesc_c locdesc_entry = 0;
            Dwarf_Unsigned expression_offset = 0;
            Dwarf_Unsigned locdesc_offset = 0;

            res = dwarf_get_locdesc_entry_d(loclist_head, i,
            &lle_value,
            &rawval1, &rawval2,
            &debug_addr_unavailable,
            &lopc,&hipc,
            &loclist_expr_op_count,
            &locdesc_entry,
            &lkind,
            &expression_offset,
            &locdesc_offset,
            &err);

            if(res==DW_DLV_OK){
                // get entry successfully
                Dwarf_Small op = 0;
                int opres;
                printf("\n");
                printindent(indent+1);
                printf("--- exp start %llx %llx\n", lopc, hipc);
                
                for(Dwarf_Unsigned j = 0; j<loclist_expr_op_count; j++){
                    Dwarf_Unsigned op1, op2, op3, offsetForBranch;

                    opres = dwarf_get_location_op_value_c(locdesc_entry, j, &op, &op1, &op2, &op3, &offsetForBranch, &err);
                    if(opres == DW_DLV_OK){
                        const char *op_name;
                        res = dwarf_get_OP_name(op, &op_name);
                        // printf("\n");
                        printindent(indent+1);
                        printf("%s ", op_name);
                        printf(" %x %x %x\n", op1, op2, op3);
                    }
                }
            }

        }
    }
    dwarf_dealloc_loc_head_c(loclist_head);
    if(loc_form == DW_FORM_sec_offset){

    }else if(loc_form == DW_FORM_exprloc){

    }

    return ret;
}
void walkDieTree(Dwarf_Debug dbg, Dwarf_Die fa_die, bool is_info, int indent){
    Dwarf_Error err;
    do{
        const char *tag_name;
        Dwarf_Half tag;
        Dwarf_Die child_die;
        int res = 0;
        res = dwarf_tag(fa_die, &tag, &err);
        if(res==DW_DLV_OK){
            res = dwarf_get_TAG_name(tag, &tag_name);
            if (res == DW_DLV_OK){
                printindent(indent);
                printf("%s", tag_name);

            }

            if (tag==DW_TAG_variable||tag==DW_TAG_formal_parameter){
                Dwarf_Bool hasLoc = false;
                char *var_name;
                Dwarf_Half name_form;
                Dwarf_Attribute name_attr;
                res = dwarf_attr(fa_die, DW_AT_name, &name_attr, &err);
                if(res == DW_DLV_OK){
                    dwarf_whatform(name_attr, &name_form, &err);
                    if(name_form==DW_FORM_string||name_form==DW_FORM_line_strp||name_form==DW_FORM_strp){
                        res = dwarf_formstring(name_attr, &var_name, &err);
                        if(res == DW_DLV_OK){
                            printf(" name: %s", var_name);
                        }
                    }
                }

                res = dwarf_hasattr(fa_die, DW_AT_location, &hasLoc, &err);
                
                
                if(res == DW_DLV_OK && hasLoc){
                    Dwarf_Attribute location_attr;
                    dwarf_attr(fa_die, DW_AT_location, &location_attr, &err);
                    Dwarf_Half form;
                    dwarf_whatform(location_attr, &form, &err);
                    const char *form_name;
                    res = dwarf_get_FORM_name(form, &form_name);
                    if(res == DW_DLV_OK){
                        printf(" %s", form_name);
                        fprintf(stderr, "%s\n", form_name);
                    }
                    // processLocation(location_attr, form, indent);
                    test_evaluator(dbg, fa_die);
                }
            }

            printf("\n");
        }

        if(dwarf_child(fa_die, &child_die, &err)==DW_DLV_OK){
            walkDieTree(dbg, child_die, is_info, indent+1);
        }
        
    }while(dwarf_siblingof_b(dbg, fa_die, is_info, &fa_die, &err) == DW_DLV_OK);
}



int main(int argc, char *argv[]) {
    const char *progname = argv[1];
    int fd = open(progname, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /*
        main process
    */
    Dwarf_Debug dbg;
    Dwarf_Error err;
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header, typeoffset;
    Dwarf_Half version_stamp, address_size, length_size, extension_size, header_cu_type;
    Dwarf_Sig8 type_signature;
    if (dwarf_init_b(fd, DW_GROUPNUMBER_ANY , NULL, NULL, &dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "dwarf_init failed: %s\n", dwarf_errmsg(err));
        return 1;
    }

    Dwarf_Die cu_die;
    bool is_info = true;
    int res = 0;
    bool isFirstCu = true;
    while(1){
        res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &length_size, &extension_size, 
            &type_signature, &typeoffset, &next_cu_header, &header_cu_type, &err);
        if (res==DW_DLV_ERROR){
            return 1;
        }
        if (res==DW_DLV_NO_ENTRY){
            if(is_info){
                is_info = false;
                continue;
            }
            return 1;
        }
        printf("cu_header_length:%llu\nnext_cu_header:%llu\n", cu_header_length, next_cu_header);

        if (dwarf_siblingof_b(dbg, NULL, is_info, &cu_die, &err) != DW_DLV_OK) {
            fprintf(stderr, "Error in dwarf_siblingof: %s\n", dwarf_errmsg(err));
            return 1;
        }

        walkDieTree(dbg, cu_die, is_info, 0);

        if(isFirstCu){
            isFirstCu = false;
        }
    }
    dwarf_finish(dbg);
    close(fd);

    return 0;
}
