#! /usr/local/bin/python3

'''
    parse a C expression and extract variable-use information

    json format of return info:

    [
        {
            "type" : <int>
            /*  0 basic 1 struct/union 2 array
                1, 2 means need deref before use
            */
            "name" : <string>
        }
    ]
'''

from ply.lex import lex
from ply.yacc import yacc

import json
from typing import Tuple, List
from enum import Enum
import sys
from findType import findType

class AccessType(Enum):
    normal = 0
    field = 1
    pointer = 2 
    array = 3
    virtual = 4
    constant = 5
    

# for debug
origin_input = ""

selfTypes = set()

class Access:

    def __init__(self, type = AccessType.normal) -> None:
        self.name:str = ""
        self.type:AccessType = type
        
        # for pointer
        self.need_deref = False # has '*' on the left

        # for struct/union
        self.ptrTo:Access = None
        self.ptrType:int = 0
        self.container:Access = None
        # 0 means '.', 1 means '->'
        self.containType:int = 0
        
        # for array
        self.need_subscript = False
        self.dimension:int = 0
        self.indAccessLsts:list[list[Access]] = []
    
    def __repr__(self) -> str:
        return f"name : {self.name}\
    type : {self.type}"


    def match(self, name:str) -> bool:
        if self.name == name:
            return True

        p:Access = self
        while p.container:
            p = p.container
        if p.name == name:
            return True
        
        return False


    def getName(self):
        name = self.name
        if self.type == AccessType.field:
            p:Access = self
            while p.container:
                p = p.container
                name = p.name + "->" + name
        
        elif self.type == AccessType.array:
            name += "[]"*self.dimension

        return name

# representative variable and all accessed variables
ResultType = Tuple[Access, List[Access], str]


        

reserved = {
    'char' : "CHAR",
    'short' : "SHORT",
    'int' : "INT",
    'long' : "LONG",
    'double' : "DOUBLE",
    'signed' : "SIGNED",
    'unsigned' : 'UNSIGNED',
    'float' : "FLOAT",
    'const' : "CONST",
    'volatile' : "VOLATILE",
    'sizeof' : "SIZEOF",
    'struct' : "STRUCT",
    'union' : "UNION"
}


# --- Tokenizer

tokens = ( 'ID', 'NUMBER' ,'STRING', 'CH',
          'PTR_OP',
          'LEFT_OP', 'RIGHT_OP', 'INC_OP', 'DEC_OP', 'AND_OP', 'OR_OP',
          'LE_OP', 'GE_OP', 'NE_OP', 'EQ_OP',
          'RIGHT_ASSIGN', 'LEFT_ASSIGN', 'ADD_ASSIGN', 'SUB_ASSIGN', 'MUL_ASSIGN', 'DIV_ASSIGN', 'MOD_ASSIGN',
          'AND_ASSIGN', 'OR_ASSIGN', 'XOR_ASSIGN',
          'STRUCT', 'UNION', 'ENUM',
          'ALIGNOF', 'SIZEOF',
          'VOID', 'CHAR', 'SHORT', 'INT', 'LONG', 'FLOAT', 'DOUBLE', 'SIGNED', 'UNSIGNED', 'BOOL',
          'CONST', 'RESTRICT', 'VOLATILE', 'ATOMIC',
          'SELFTYPE')

literals = "+-*/%=" + "()[]{}<>" + "*|?^~!" + ".,&:"

t_ignore = ' \t'

# Token matching rules are written as regexs
# t_ID = r'[a-zA-Z_][a-zA-Z0-9_]*'
t_STRING = r'"[^"]*"'       # may be not correct
t_CH = r'\'[^\']\''
t_PTR_OP = r'->'
t_LEFT_OP = r'<<'
t_RIGHT_OP = r'>>'
t_INC_OP = r'\+\+'
t_DEC_OP = r'--'
t_AND_OP = r'&&'
t_OR_OP = r'\|\|'

t_LE_OP = r'<='
t_GE_OP = r'>='
t_NE_OP = r'!='
t_EQ_OP = r'=='

t_RIGHT_ASSIGN = r'>>='
t_LEFT_ASSIGN = r'<<='
t_ADD_ASSIGN = r'\+='
t_SUB_ASSIGN = r'-='
t_MUL_ASSIGN = r'\*='
t_DIV_ASSIGN = r'/='
t_MOD_ASSIGN = r'%='
t_AND_ASSIGN = r'&='
t_OR_ASSIGN = r'\|='
t_XOR_ASSIGN = r'^='

t_STRUCT = r'struct'
t_UNION = r'union'
t_ENUM = r'enum'

t_ALIGNOF = r'__alignof__'
t_SIZEOF = r'sizeof'

t_VOID = r'void'
t_CHAR = r'char'
t_SHORT = r'short'
t_INT = r'int'
t_LONG = r'long'
t_FLOAT = r'float'
t_DOUBLE = r'double'
t_SIGNED = r'signed'
t_UNSIGNED = r'unsigned'
t_BOOL = r'bool|_Bool'

t_CONST = r'const'
t_RESTRICT = r'restrict'
t_VOLATILE = r'volatile'
t_ATOMIC = r'_Atomic'

# A function can be used if there is an associated action.
# Write the matching regex in the docstring.

def t_NUMBER(t):
    r'0x[\da-fA-F]+|\d+'    # only consider integer now
    return t


def t_ID(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    t.type = reserved.get(t.value, "ID")
    if t.value in selfTypes:
        t.type = "SELFTYPE"
    return t


# Ignored token with an action associated with it
def t_ignore_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count('\n')

# Error handler for illegal characters
def t_error(t):
    print(f'Illegal character {t.value[0]!r} for {origin_input}', file=sys.stderr)
    t.lexer.skip(1)

# Build the lexer object
# lexer = lex()
    

# --- Parser

def merge_access_list(p, poses:list[int]):
    res = []
    for pos in poses:
        if len(p) > pos and type(p[pos]) == tuple and len(p[pos]) > 1:
            res.extend(p[pos][1])
    return res

def getStr(p_obj):
    if type(p_obj) == str:
        return p_obj
    elif type(p_obj) == tuple and len(p_obj) > 2:
        return p_obj[2]
    else:
        return ""

def p_type_name(p):
    '''
    type_name : specifier_qualifier_list pointer
	    | specifier_qualifier_list
    '''
    p[0] = ' '.join(p[1:])

def p_specifier_qualifier_list(p):
    '''
    specifier_qualifier_list : type_specifier specifier_qualifier_list
        | type_specifier
        | type_qualifier specifier_qualifier_list
        | type_qualifier
    '''
    p[0] = ' '.join(p[1:])

def p_pointer(p):
    '''
    pointer : '*' type_qualifier_list pointer
        | '*' type_qualifier_list
        | '*' pointer
        | '*'
    '''
    p[0] = ' '.join(p[1:])

def p_type_specifier(p):
    '''
    type_specifier : VOID
        | CHAR
        | SHORT
        | INT
        | LONG
        | FLOAT
        | DOUBLE
        | SIGNED
        | UNSIGNED
        | BOOL
        | STRUCT ID
        | UNION ID
        | ENUM ID
        | SELFTYPE		
    '''
    p[0] = p[1]

def p_type_qualifier_list(p):
    '''
    type_qualifier_list : type_qualifier
	    | type_qualifier_list type_qualifier
    '''
    p[0] = ' '.join(p[1:])

def p_type_qualifier(p):
    '''
    type_qualifier : CONST
        | RESTRICT
        | VOLATILE
        | ATOMIC
    '''
    p[0] = p[1]

def p_postfix_expression(p:list[ResultType]):
    '''
    postfix_expression : primary_expression
        | postfix_expression '[' expression ']'
        | postfix_expression '(' ')'
        | postfix_expression '(' argument_expression_list ')'
        | postfix_expression '.' ID
        | postfix_expression PTR_OP ID
        | postfix_expression INC_OP
        | postfix_expression DEC_OP
    '''    
    
    if len(p) == 2:
        p[0] = p[1]
        return
    
    old:ResultType = p[1]
    var:Access = old[0]

    if p[2] == '[' :
        # postfix_expression '[' expression ']'
        
        var.type = AccessType.array
        var.dimension += 1
        var.indAccessLsts.append(merge_access_list(p, [3]))
        var.need_subscript = True

        p[0] = (var, merge_access_list(p, [1,3]))


    elif len(p) == 5 and p[2] == '(':
        # postfix_expression '(' argument_expression_list ')'

        #! may be function pointer, still access it

        p[0] = (Access(AccessType.virtual), merge_access_list(p, [1,3]))
                
    
    elif p[2] == '->':
        # postfix_expression PTR_OP ID

        field = Access()
        field.name = p[3]
        field.container = var
        field.containType = 1
        field.type = AccessType.field
        var.ptrTo = field
        var.ptrType = 1

        
        p[0] = (field, old[1] + [field])

    elif p[2] == '.':
        # postfix_expression '.' ID

        field = Access()
        field.name = p[3]
        field.container = var
        field.containType = 0
        field.type = AccessType.field
        var.ptrTo = field
        var.ptrType = 0
        
        p[0] = (field, old[1] + [field])

    else:

        p[0] = p[1]

def p_primary_expression(p:str):
    '''
    primary_expression : ID
        | NUMBER
        | STRING
        | CH
        | '(' expression ')'
    '''
    if p[1].startswith('\''):
        pass
        
    elif p[1].startswith('"'):
        pass
    elif p[1].startswith('('):
        
        p[0] = p[2]

    elif '0' <= p[1][0] <= '9':
        pass
    else:
        # ID
        var:Access = Access()
        var.name = p[1]

        p[0] = (var, [var])
        

def p_argument_expression_list(p):
    '''
    argument_expression_list : assignment_expression
	    | argument_expression_list ',' assignment_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (p[3][0] if p[3] else None, merge_access_list(p, [1,3]))

def p_unary_expression(p):
    '''
    unary_expression : postfix_expression
        | INC_OP unary_expression
        | DEC_OP unary_expression
        | unary_operator cast_expression
        | SIZEOF '(' unary_expression ')'
        | SIZEOF '(' type_name ')'
        | ALIGNOF '(' type_name ')'
    '''
    if len(p) == 2:
        p[0] = p[1]
    
    elif p[1] == '++' or p[1] == '--':
        p[0] = p[1]
    
    elif p[1] == 'sizeof' or p[1] == '__alignof__':
        p[0] = (None, [])
    
    elif p[1] == '*':
        # * cast_expression

        
        var:Access = p[2][0] if type(p[2]) == tuple and p[2][0] else Access(AccessType.virtual)
        var.need_deref = True
        
        access_lst = p[2][1] if type(p[2]) == tuple and len(p[2]) > 1 else []
    
        p[0] = (var, access_lst)
    
    elif p[1] == '&':

        var:Access = p[2][0] if type(p[2]) == tuple and p[2][0] else Access(AccessType.virtual)
        var.type = AccessType.pointer

        p[0] = p[2] if type(p[2]) == tuple and p[2][0] else (var, p[2][1])


def p_unary_operator(p):
    '''
    unary_operator : '&'
        | '*'
        | '+'
        | '-'
        | '~'
        | '!'
    '''
    p[0] = p[1]

def p_cast_expression(p):
    '''
    cast_expression : unary_expression
	    | '(' type_name ')' cast_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[4]

def p_multiplicative_expression(p):
    '''
    multiplicative_expression : cast_expression
        | multiplicative_expression '*' cast_expression
        | multiplicative_expression '/' cast_expression
        | multiplicative_expression '%' cast_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        
        p[0] = (None, merge_access_list(p, [1,3]))

def p_additive_expression(p):
    '''
    additive_expression : multiplicative_expression
        | additive_expression '+' multiplicative_expression
        | additive_expression '-' multiplicative_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_shift_expression(p):
    '''
    shift_expression : additive_expression
    	| shift_expression LEFT_OP additive_expression
	    | shift_expression RIGHT_OP additive_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_relational_expression(p):
    '''
    relational_expression : shift_expression
        | relational_expression '<' shift_expression
        | relational_expression '>' shift_expression
        | relational_expression LE_OP shift_expression
        | relational_expression GE_OP shift_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_equality_expression(p):
    '''
    equality_expression : relational_expression
        | equality_expression EQ_OP relational_expression
        | equality_expression NE_OP relational_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_and_expression(p):
    '''
    and_expression : equality_expression
        | and_expression '&' equality_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_exclusive_or_expression(p):
    '''
    exclusive_or_expression : and_expression
	    | exclusive_or_expression '^' and_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_inclusive_or_expression(p):
    '''
    inclusive_or_expression : exclusive_or_expression
	    | inclusive_or_expression '|' exclusive_or_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_logical_and_expression(p):
    '''
    logical_and_expression : inclusive_or_expression
	    | logical_and_expression AND_OP inclusive_or_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_logical_or_expression(p):
    '''
    logical_or_expression : logical_and_expression
	    | logical_or_expression OR_OP logical_and_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))

def p_conditional_expression(p):
    '''
    conditional_expression : logical_or_expression
	    | logical_or_expression '?' expression ':' conditional_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3,5]))

def p_assignment_expression(p):
    '''
    assignment_expression : conditional_expression
	    | unary_expression assignment_operator assignment_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))


def p_assignment_operator(p):
    '''
    assignment_operator : '='
        | MUL_ASSIGN
        | DIV_ASSIGN
        | MOD_ASSIGN
        | ADD_ASSIGN
        | SUB_ASSIGN
        | LEFT_ASSIGN
        | RIGHT_ASSIGN
        | AND_ASSIGN
        | XOR_ASSIGN
        | OR_ASSIGN
    '''
    p[0] = p[1]

def p_expression(p):
    '''
    expression : assignment_expression
	    | expression ',' assignment_expression
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = (None, merge_access_list(p, [1,3]))



def p_error(p):
    print(f'Syntax error at {p!r} for {origin_input}', file=sys.stderr)



class ExpParser:
    def __init__(self) -> None:
        
        self.lexer = lex()
        self.parser = yacc(start='expression')
        
    
    def parse(self, expression:str = "", types:set = set(), debug:bool = False, show_exp:bool = False):
        if show_exp:
            global origin_input
            origin_input = expression
        
        global selfTypes
        
        selfTypes = types
        
        result = self.parser.parse(expression, lexer = self.lexer, debug = debug)
        return result


if __name__ == "__main__":
    parser = ExpParser()
    res = parser.parse("sizeof(unsigned long)")
    print(res)


''' test cases

dev -> ethtool_ops-> get_link_ksettings
snd_hda_add_pincfg ( codec , & codec -> user_pins , nid , cfg )

tolower ( ( int ) * ( * string + 1 ) )
sprintf ( buffer + result , "%-25s\t0x%08X [%c]\n" , "ACPI_ALL_DRIVERS" , ACPI_ALL_DRIVERS , ( acpi_dbg_layer & ACPI_ALL_DRIVERS ) == ACPI_ALL_DRIVERS ? '*' : ( acpi_dbg_layer & ACPI_ALL_DRIVERS ) == 0 ? ' ' : '-' )
( value ) & 255
( ( ( value ) >> 8 ) & 0xFF )
( op == INTEL_GT_SYSFS_MAX ) ? 0 : ( u32 ) - 1
* ( data + frame_size / 2 + 12 )
* ( skb -> data + frame_size / 2 + 12 )
*++ p
* ( dptr - 1 )
* ( dptr - 1 )
* ( dptr - 1 )
cap_capable ( current_cred ( ) , current_cred ( ) -> user_ns , CAP_SETPCAP , CAP_OPT_NONE )
'''