"""
    This module contains code for using the shell interpreter which is used in the main.py file.
"""
from os import system

# Useful string constants
HELP = "help"
CLEAR = "clear"
EXIT = "exit"
LIST = "list"

def clear_screen():
    system("clear")

def print_menu():
    clear_screen()
    print("Welcome to the Backdoor Command Shell!")
    print("Enter 'help' for a list of commands")

def print_help():
    print("Possible Commands:")
    print("help " + 5*"\t" + " Displays this help screen.")
    print("clear " + 5*"\t" + " Clears the terminal screen.")
    print("exit " + 5*"\t" + " End the terminal session.")

