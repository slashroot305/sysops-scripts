#!/usr/bin/python3

import secrets, string

random_string = ''.join(
    secrets.choice(string.ascii_letters + string.digits + string.punctuation)
        for _ in range(16))

print(random_string)
