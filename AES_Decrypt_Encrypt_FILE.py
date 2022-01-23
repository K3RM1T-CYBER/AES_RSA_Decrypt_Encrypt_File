import base64
import string
import random
import os
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

BLOCK_SIZE = 16  # Constant to set block size for AES operation


def rsa_generate_keys():
    """Generate RSA KEY PAIR.

    Returns:
            int : 0
    """
    key = RSA.generate(4096)
    public_key = key.public_key().exportKey('PEM').decode()
    public_key_file = open('publicKey.pem', 'w')
    public_key_file.write(public_key)  # Writing the public key to the publicKey.pem file
    public_key_file.close()
    print(f'CLE PUBLIQUE OK\n')

    private_key = key.exportKey('PEM').decode()
    private_key_file = open('privateKey.pem', 'w')
    private_key_file.write(private_key)  # Writing the private key to the privateKey.pem file
    private_key_file.close()
    print(f'CLE PRIVÉE OK\n')

    return 0


def rsa_encrypt_creds(message):
    """Encrypts a string with rsa and saves it in a credentials.cre file.

        Args:
            message (str) : string to encrypt with RSA

        Returns:
            int : 0
    """
    key_text = open(input("Enter the name of the file containing the recipient's RSA public key: "), "rb").read()
    public_key = RSA.importKey(key_text)  # Imports the recipient's public key
    cipher = PKCS1_v1_5.new(public_key)
    message = message.encode()
    encrypted_bytes = cipher.encrypt(message)  # Encrypt decryption information with RSA
    saved_credentials_file = open("credentials.cre", 'wb')
    saved_credentials_file.write(encrypted_bytes)  # Write decryption information to the credentials.cre file
    saved_credentials_file.close()
    print(f'All is good, You can send the encrypted file and the credentials.cre file to your recipient')
    return 0


def rsa_decrypt_creds():
    """Decrypts a file encrypted with RSA


        Returns:
            str : decrypted string with RSA
    """
    private_key = open(input("Enter the name of the file containing your RSA private key: "), "rb").read()
    credentials_encrypted = open(input("Enter the name of the file containing the decryption information (.cre) : "),
                                 'rb').read()
    private_key = RSA.importKey(private_key)  # Import the recipient's private key from the file
    cipher = PKCS1_v1_5.new(private_key)
    decrypted_credentials = cipher.decrypt(credentials_encrypted, "ERROR")  # Decrypts information from .cre file
    return str(decrypted_credentials.decode())


def gen_password():
    """Generates a 16 character long random password containing numbers and letters


        Returns:
            bytes : the generated password
    """
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for i in range(16))
    password = bytes(password, 'utf-8')
    return password


def aes_encrypt_data(file):
    """Encrypts a file with the AES method and saves in a file name_file.extension.enc

        Args:
            file (str) : file to encrypt with the AES method

        Returns:
            int : 0
    """
    name_file = file
    file = open(file, "rb")
    data_file = file.read()
    length = 16 - (len(data_file) % 16)  # Avoid block size error by adjusting length
    data_file += bytes([length]) * length
    password = gen_password()
    IV = Random.new().read(BLOCK_SIZE)  # Generate 16 random bytes for the initialization vector (IV)
    IV64 = base64.b64encode(IV)
    aes = AES.new(password, AES.MODE_CBC, IV)  # Generate an AES method using the password and the IV
    print(f'Encryption in progress ...\n')
    data_encrypt = aes.encrypt(data_file)  # Encrypt file data with AES
    new_file = open(name_file + '.enc', 'wb')
    new_file.write(data_encrypt)
    new_file.close()
    print(f'AES encryption done !')
    credentials_rsa_encrypted = rsa_encrypt_creds(str(IV64.decode()) + "---" + password.decode())
    return 0


def aes_decrypt_data(file):
    """Decrypts a file with the AES method and saves in a file name_file.extension

        Args:
            file (str) : file to decrypt with the AES method

        Returns:
            int : 0
    """
    name_file = file.replace(".enc", "")
    file = open(file, "rb")
    data_file = file.read()
    credentials_string = rsa_decrypt_creds()  # Decrypt .cre data encrypt with RSA
    pos_separator = credentials_string.find("-")  # Separate the data from the .created file into a mdp and an IV
    IV = credentials_string[0:pos_separator]
    password = credentials_string[pos_separator + 3:].encode()
    IV = base64.b64decode(IV.encode())
    aes = AES.new(password, AES.MODE_CBC, IV)  # Creating an AES method with the password and the IV
    print(f'Decryption in progress...')
    data_decrypt = aes.decrypt(data_file)  # Decrypt .enc file data
    new_file = open(name_file, 'wb')
    new_file.write(data_decrypt)
    new_file.close()
    print(f'Decryption done...If your file cannot open, your credentials file is invalid')
    return 0


def main():
    print("#############################################")
    print("########## ENCRYPT - DECRYPT AES ############")
    print("#############################################")
    print(f'\nWelcome to this tool developed by K3RM1T, what do you want to do?\n')
    print(f'   1: Encrypt a file')
    print(f'   2: Decrypt a file')
    print(f'   3: Generate an RSA key pair\n')
    result_choice = ""
    while result_choice != '1' or '2' or '3':
        result_choice = input("Enter your choice : ")
        if result_choice == '1':
            check_file_encrypt = False
            while not check_file_encrypt:
                file = input("Enter the name of the file to encrypt : ")
                if os.path.isfile(file):
                    check_file_encrypt = True
                    aes_encrypt_data(file)
                else:
                    print("\nFile doesnt not exist, try again")
        elif result_choice == '2':
            check_file_decrypt = False
            while not check_file_decrypt:
                file = input("Enter the name of the file to encrypt : ")
                if os.path.isfile(file) and file[-4:] == ".enc":
                    check_file_decrypt = True
                    aes_decrypt_data(file)
                else:
                    print("\nFile doesnt not exist or the file extension is not .enc")
            aes_decrypt_data(input("Enter the name of the file to decrypt : "))
        elif result_choice == '3':
            rsa_generate_keys()
        print(f'Choice error, try again')


if __name__ == '__main__':
    main()
