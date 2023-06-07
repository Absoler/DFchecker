#! /usr/local/bin/python3
import clang.cindex
import sys
import os
import json


cached_types = []

def print_ast(cursor, depth=0):
    print('  ' * depth + f'{cursor.kind.name} ({cursor.type.spelling}) - {cursor.spelling}')

    for child in cursor.get_children():
        print_ast(child, depth + 1)



def extract_typedef_names(cursor):
    res = set()
    if cursor.kind == clang.cindex.CursorKind.TYPEDEF_DECL:
        res.add(cursor.spelling)
        for child in cursor.get_children():
            if child.kind == clang.cindex.CursorKind.TYPE_REF:
                alias_name = child.spelling
                res.add(alias_name)
                break

    # Recurse through the children
    for child in cursor.get_children():
        res = res.union(extract_typedef_names(child))
    
    return res


def process_file(file_path:str, index:clang.cindex.Index, visit:set):
    res = set()

    # need specify include path with `-I/path` format in `args`
    tu = index.parse(file_path, args=[])

    # Extract typedef names
    res = extract_typedef_names(tu.cursor)
    visit.add(file_path)

    # Process included files
    for include in tu.get_includes():
        included_file_path = include.include.name
        if included_file_path in visit:
            continue
        res = res.union(process_file(included_file_path, visit))

    return res

def createCache_map(repo_path:str = "", src_list:list = []):
    if src_list == []:
        src_list = (os.popen(f"find {repo_path} -name \"*.c\"").read()).split('\n')
        del src_list[-1]
    
    file_typesMp = {}
    for src in src_list:
        types = process_file(src, [])
        file_typesMp[src] = types
    
    print(json.dumps(("map", file_typesMp), indent=4))

def createCache_list(repo_path:str = "", src_list:list = []):
    if src_list == []:
        src_list = (os.popen(f"find {repo_path} -name \"*.c\"").read()).split('\n')
        del src_list[-1]
    
    all_types = set()
    index = clang.cindex.Index.create()

    for src in src_list:
        tu = index.parse(src)
        types = extract_typedef_names(tu.cursor)
        for t in types:
            all_types.add(t)
        print(f"parse {src} types", file=sys.stderr)
    
    print(json.dumps(("list", list(all_types)), indent=4))


def findType(file_path:str = "", repo_path:str = "", use_cache:bool = True) -> set:
    # Provide the path to the C repository

    all_types = set()

    types_filename = os.path.normpath(repo_path + "/types.json")
    if use_cache and os.path.exists(types_filename):
        global cached_types
        if cached_types == []:
            f = open(types_filename, "r")
            cached_types = json.load(f)
            f.close()

        if cached_types[0] == "map" and file_path != "":
            return set(cached_types[1][os.path.normpath(file_path)])
        
        elif cached_types[0] == "list":
            return set(cached_types[1])
        
        else:
            return None
    
    
    if file_path != "":
        src_list = [file_path]
    else:
        src_list = (os.popen(f"find {repo_path} -name \"*.c\"").read()).split('\n')
        del src_list[-1]

    print(f"extract types from {len(src_list)} file(s) in total uncached", file=sys.stderr)

    # Initialize libclang and create an index
   
    index = clang.cindex.Index.create()
    for src in src_list:
        try:
            
            types = process_file(src, index, [])
            
            all_types = all_types.union(types)

            print(f"parse {src} done", file=sys.stderr)
        
        except Exception as e:
            print(f"fail at {src} with {e.__repr__()}", file=sys.stderr)
    

    return all_types



'''
最初想法是只寻找待分析表达式所在文件中的自定义类型，但是这样做需要显示指定include路径，不然
可能会和系统头文件冲突，尤其是在分析linux kernel的时候

现在做法退化到直接记录待分析项目中所有的自定义类型，对每个要分析的表达式，都认为它能够使用所有类型

可能的问题：一个编译单元的自定义类型可能和另一个编译单元的变量重名，目前只能假定没有这种情况出现了
'''

if __name__ == '__main__':
    createCache_list(sys.argv[1])

