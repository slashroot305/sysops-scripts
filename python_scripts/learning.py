password_file = open('SecretPasswordFile.txt')
secret_password = password_file.read()
print('Enter your password:')
typeed_password = input()
if typeed_password == secret_password:
    print('Access granted')
    if typeed_password == '12345':
        print("You're and idiot")
    else:
        print("Access granted")