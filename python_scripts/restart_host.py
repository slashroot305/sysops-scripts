#!/usr/bin/python3

# reboot script

import os

def shutdown_computer():
    #for Windows OS
    if os.name == 'nt':
        os.system('shutdown /r /t 1')
        #for Unix/Linux/Mac OS
    elif os.name == 'posix':
        os.system('sudo shutdown -r +1')
    else:
        print('Unsupported OS')
        
shutdown_computer()