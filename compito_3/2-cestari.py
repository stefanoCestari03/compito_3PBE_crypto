# exercise 
# import chiper modules:
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# exaple of graphic
import tkinter as tk
from tkinter import filedialog, simpledialog
from tkinter import ttk


# import of other modules 
#import lec2
import sys 
import getpass
import os


# class of exceptions
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''
class KeyDerivationError(SymEncError):
    '''Key derivation error'''

def generate_key_byKDF(password,salt):
    # script function to derivate a key from a password/passphrase
    key = scrypt(password, salt, 16, N=2**14, r=8, p=1)
    return key

# initializating vector
def generate_iv():
    return get_random_bytes(16)

def encrypt_file(in_file, out_file, password, iv):
    try:
        salt = get_random_bytes(16)
        key = generate_key_byKDF(password,salt)
    except:
        raise KeyDerivationError
    try:
        
        cipher = AES.new(key, AES.MODE_GCM, iv)
        try:
            with open(in_file, 'rb') as file:
                plain_text = file.read()
        except IOError as err:
            err_str = 'Error: Cannot read file "'
            err_str += path + '": ' + str(err)
            print(err_str)
        cipher_text, auth_tag = cipher.encrypt_and_digest(plain_text)
        
       
        cipher_text += auth_tag
        # adding salt at the end of the cipher txt file
        cipher_text += salt 
        try:
            # text files tests
            # with open(out_file + '.enc', 'wb') as file:
            # immage test use extension of the file jpg
            with open(out_file , 'wb') as file:
                file.write(iv + cipher_text)
        except IOError as err:
            err_str = 'Error: Cannot write file "'
            err_str += path + '": ' + str(err)
            print(err_str)
    except:
        raise ValidationError("An error occurred while trying to encrypt the file")

def decrypt_file(in_file, out_file, password):
    try:
        with open(in_file, 'rb') as file:
            iv = file.read(16)
            text_to_decrypt = file.read()
    except IOError as err:
        err_str = 'Error: Cannot read file "'
        err_str += path + '": ' + str(err)
        print(err_str)
    # removing salt from the file
    try:
        # extracting the salt from the end of the file
        salt =  text_to_decrypt[-16:]
        # removing salt from the encrypted data creating a new substring
        text_to_decrypt = text_to_decrypt[:-16]
        # using salt and password to generate the same key  that was used for encryption
        key = generate_key_byKDF(password,salt)
    except:
        raise KeyDerivationError
    cipher = AES.new(key, AES.MODE_GCM, iv)
    # extracting out tag from the end of the file
    auth_tag = text_to_decrypt[-16:]
    text_to_decrypt = text_to_decrypt[:-16]
    try:
        cipher_text = cipher.decrypt_and_verify(text_to_decrypt, auth_tag)
    except:
        raise ValidationError("wrong password")
    plain_text = cipher_text
    try: 
        with open(out_file , 'wb') as file:
            file.write(plain_text)
    except IOError as err:
        err_str = 'Error: Cannot write file "'
        err_str += path + '": ' + str(err)
        print(err_str)
      
    
# main

# terminal main
# def main():
#     prompt = '''Welcome to  Crypto lab chose a way to Chiper:\n
#     1. Encrypt 3DES\n
#     2. Decrypt 3DES\n
#     \n\ninsert your choice: '''
#     # key initialization
#     key = ""
#     while True:
#         choice = input(prompt)
#         if choice == '1':
#             in_file = input("insert path of the file to encrypt: ")
#             out_file = input("insert path of the file in output: ")
#             key_file = input("insert path of the keyfile: ")
#             key = generate_key(key_file)
#             encrypt_file(in_file, out_file, key)
#             #encrypt_file(in_file, out_file, key_file)
#         elif choice == '2':
#             in_file = input("insert path of the file to decrypt: ")
#             out_file = input("inserte path of the file in output: ")
#             decrypt_file(in_file, out_file, key)
#             #decrypt_file(in_file, out_file, key_file)
#         else:
#             sys.exit()
        
# if __name__ == "__main__":
#     main()




# GUI execution of the exercise
class CryptoApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Crypto Lab")
        self.master.geometry("600x400")
        self.password = ""
        self.create_widgets()

    def create_widgets(self):
        style = ttk.Style()
        style.configure('TButton', padding=5, font=('Helvetica', 12))

        self.label = tk.Label(self.master, text="Welcome to Crypto lab, choose what to do:", font=('Helvetica', 16))
        self.label.pack(pady=10)

        self.encrypt_button = ttk.Button(self.master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = ttk.Button(self.master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

    def encrypt(self):
        in_file = filedialog.askopenfilename(title="SELECT FILE TO ENCRYPT")
        # Pop up for password input
        self.password = simpledialog.askstring("Password", "Enter a new password valid for this file:", show='*')
        # outfile name check
        out_file = filedialog.asksaveasfilename(title="TYPE THE NAME OF THE (enc) FILE AND CLICK SAVE")
        encrypt_file(in_file, out_file, self.password, generate_iv())

    def decrypt(self):
        in_file = filedialog.askopenfilename(title="SELECT FILE TO DECRYPT")

        # Pop up for password input
        self.password = simpledialog.askstring("Password", "Enter file's password:", show='*')

        out_file = filedialog.asksaveasfilename(title="TYPE THE NAME OF THE (dec) FILE AND CLICK SAVE")
        decrypt_file(in_file, out_file, self.password)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
