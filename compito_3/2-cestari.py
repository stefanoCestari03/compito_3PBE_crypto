# exercise 
# import chiper modules:
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad
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
class EncryptingError(Exception): 
    '''Error, problems with encryption'''
class DecryptingError(Exception): 
    '''Error, problems with decription'''
class AutenticationError(Exception):
    '''Error, Autentication file failed! '''
class ReadingFileError(Exception):
    '''Error, during read of the file'''
class WritingFileError(Exception):
    '''Error, during read of the file'''
class KeyGenerationError(Exception):
    '''Error during generation of the key'''
class KeySavingError(Exception):
    '''Error during saving proces of the key'''

# unpadding text

def unpad(data):
    length = 8 * ((len(data) + 7) // 8)
    return data[:length]

# key generating 
def unpad(data):
    length = 16 * ((len(data) + 15) // 16)
    return data[:length]

def generate_key(password,salt):
    try:
        #faccio funzione di hash per prendere un valore dalla password
        key = scrypt(password, salt, 16, N=2**14, r=8, p=1)
    except KeyGenerationError as err:
        print(err)
    return key

def generate_iv():
    return get_random_bytes(16)

def encrypt_file(in_file, out_file, password, iv):
    salt = get_random_bytes(16)
    key = generate_key(password,salt)
    try:
        
        cipher = AES.new(key, AES.MODE_GCM, iv)
        try:
            with open(in_file, 'rb') as file:
                plain_text = file.read()
        except ReadingFileError as err:
            err += " in encrypting situation"
            print(err)
        cipher_text, auth_tag = cipher.encrypt_and_digest(plain_text)
        
        try:
            cipher_text += auth_tag
            # adding salt at the end of the cipher txt file
            cipher_text += salt 
        except AutenticationError as err:
            print(err)
        try:
            # text files tests
            # with open(out_file + '.enc', 'wb') as file:
            # immage test use extension of the file jpg
            with open(out_file , 'wb') as file:
                file.write(iv + cipher_text)
        except WritingFileError as err:
            err += " in encrypting situation"
            print(err)
    except EncryptingError as err:
        print(err)

def decrypt_file(in_file, out_file, password):
    try:
        try:
            with open(in_file, 'rb') as file:
                iv = file.read(16)
                text_to_decrypt = file.read()
            # removing salt from the file
            try:
                # extracting the salt from the end of the file
                salt =  text_to_decrypt[-16:]
                # removing salt from the encrypted data creating a new substring
                text_to_decrypt = text_to_decrypt[:-16]
                # using salt and password to generate the same key  that was used for encryption
                key = generate_key(password,salt)
            except KeyGenerationError as err:
                print(err)
            cipher = AES.new(key, AES.MODE_GCM, iv)
        except ReadingFileError as err:
            err += " in decrypting situation"
            print(err)
        # extracting out tag from the end of the file
        auth_tag = text_to_decrypt[-16:]
        text_to_decrypt = text_to_decrypt[:-16]
        cipher_text = cipher.decrypt_and_verify(text_to_decrypt, auth_tag)
        plain_text = unpad(cipher_text)
        try:
                # text tests
                # with open(out_file + '.dec', 'wb') as file:
                # immage test use extension of the file jpg
                try:
                    with open(out_file , 'wb') as file:
                        file.write(plain_text)
                except WritingFileError as err:
                    err += " in writing decrypted file situation"
                    print(err)
        except DecryptingError as err:
            print(err)
    except AutenticationError as err:
        print(err)
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
