import base64
import os
import hashlib
import string
import random
from Crypto import Random
from Crypto.Cipher import AES

block_size = 16


def genpassword():
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(16))
    password = bytes(password, 'utf-8')
    return password


def encryptdata(file):
    nameFile = file
    file = open(file, "rb")
    dataFile = file.read()
    length = 16 - (len(dataFile) % 16)
    dataFile += bytes([length]) * length
    password = genpassword()
    IV = Random.new().read(block_size)
    IV64 = base64.b64encode(IV)
    aes = AES.new(password, AES.MODE_CBC, IV)
    print("Encryption in progress ...\n")
    dataEncrypt = aes.encrypt(dataFile)
    newFile = open(nameFile + '.enc', 'wb')
    newFile.write(dataEncrypt)
    newFile.close()
    print("Encryption done !")
    print("This is your IV, save it : " + str(IV64.decode()))
    print("This is your password : " + password.decode())


def decryptdata(file):
    nameFile = file.replace(".enc", "")
    file = open(file, "rb")
    dataFile = file.read()
    password = input("Please, enter your password : ")
    IV = input("Please, enter your IV : ")
    password = password.encode()
    IV = base64.b64decode(IV.encode())
    aes = AES.new(password, AES.MODE_CBC, IV)
    print("Decryption in progress...")
    dataDecrypt = aes.decrypt(dataFile)
    newFile = open(nameFile, 'wb')
    newFile.write(dataDecrypt)
    newFile.close()
    print("Decryption done...If your file cannot open, your password or IV is incorrect")



print("#############################################")
print("##### CHIFFREMENT - DECHIFFREMENT RSA #######")
print("#############################################")
print("\nBienvenue dans cet outil développé par K3RM1T, que souhaitez vous faire ?\n")
print("   1: Chiffrer un fichier")
print("   2: déchiffrer un fichier\n")
resultChoice = int(input("Entrez votre choix : "))

if resultChoice == 1:
    dataEncrypted = encryptdata(input("Entrez le nom du fichier à chiffrer : "))

if resultChoice == 2:
    dataDecrypted = decryptdata(input("Entrez le nom du fichier à déchiffrer : "))
