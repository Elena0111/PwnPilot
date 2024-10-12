import argparse
import sys
from typing import Iterable, Any


def get_arguments(args: Iterable[Any]) -> list:
   
    """Creates a list with the parsed parameters 

    Arguments:
        args: The arguments parsed from command line.

    Returns:
        A list containing the parameters.
    """

    binary_name = args.b
    verbose = args.v
    delimiter = args.d
    attack = args.a
    fuzzing = args.f
    return [binary_name] + [verbose] + [delimiter] + [attack] +[fuzzing]


def getParameters():

    """Produce a list with the parsed parameters 

    Returns:
        A list containing the parameters.
    """

    parser = argparse.ArgumentParser(description = "PwnPilot")
    parser.add_argument("-b", type=str, help="Binary to exploit", default=None)  
    parser.add_argument("-v",type=str, help="Set verbose mode to display additional information during the exploitation process", choices=['True', 'False'], default=None)
    parser.add_argument("-d",type=str, help="When to stop reading from the process", default='\\n')
    parser.add_argument("-a",type=str, help="Type of attack to be perfomed", choices=['ret2libc', 'sigrop'])
    parser.add_argument("-f",type=str, help="Fuzzing", default = None)

    arguments = []

    args = parser.parse_args()
    list=get_arguments(args)
    arguments += list
    
    if args.b == None:
        print('Set binary file:\n -b <binary>')
        exit()

    return arguments
