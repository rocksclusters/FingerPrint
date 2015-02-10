#!/bin/bash
#
# Luca Clementi
# 
# this script tell which one of the "declared" required shared libraries
# (NEEDED entry in the elf dynamic section) is really necessary or not
#
# For an explanation of this problem: http://wiki.debian.org/ToolChain/DSOLinking
#


file=$1

symbol_list=`objdump -T $file`

for libname in `objdump -x $file |grep NEEDED|awk '{print $2}'`; do
    #find path
    libfilepath=`ldd $file |grep $libname |awk '{print $3}'`
    needed=false
    for available_sym in `objdump -T $libfilepath | grep "\.text\|\.data" | awk '{print substr($0, 62)}'`; do
        # do we need this symbol?
        if echo -e "$symbol_list" | grep $available_sym > /dev/null; then
            needed=true
            break
        fi
    done
    if $needed ;then
        echo $libname is needed
    else
        echo $libname not needed
    fi
done
