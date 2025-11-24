#!/usr/bin/python3

import random, string, secrets, tempfile, subprocess, platform, os

# generate secure random 16 char string
random_string = ''.join(
    secrets.choice(
        string.ascii_letters + string.digits)
        for _ in range(16))

'''''
# temp file with results that won't be saved
with tempfile.NamedTemporaryFile(mode='w', suffix='txt', delete=False) as temp_file:
    temp_file.write(random_string)
    temp_file_path = temp_file.name
'''''

print(random_string)

''''
try:
    if platform.system() == 'Windows':
        os.startfile(temp_file_path)
    elif platform.system() == 'Darwin' or platform.system == 'darwin': #macOS
        subprocess.run(['open', temp_file_path])
    else: # linux or other Unix-like systems
        subprocess.run(['xdg-open', temp_file_path])
except NameError as e:

    # wait for user to close the file before cleanup
    input("Press enter to start cleanup...")

finally:
    # delete the temp file
    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)
'''