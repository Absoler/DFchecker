# Introduction

this project is used for checking whether extra memory accesses are introduced in optimized-compiled program by binary analyse based on json-guide file generated by patcher (https://github.com/Absoler/patcher)


# Dependency

## binary checker on python
`pip install ply iced_x86 libclang`

## varLocator: map var's name with binary description

need install `libdwarf`, can download from [https://github.com/davea42/libdwarf-code/releases]()