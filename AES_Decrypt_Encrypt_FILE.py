"""System module"""
import base64
import string
import random
import os
import sys
from termcolor import colored
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
    public_key = key.public_key().exportKey("PEM").decode()
    with open("publicKey.pem", "w", encoding="utf-8") as public_key_file:
        public_key_file.write(
            public_key
        )  # Writing the public key to the publicKey.pem file
        public_key_file.close()
    print(colored("PUBLIC KEY OK\n", "green"))

    private_key = key.exportKey("PEM").decode()
    with open("privateKey.pem", "w", encoding="utf-8") as private_key_file:
        private_key_file.write(
            private_key
        )  # Writing the private key to the privateKey.pem file
        private_key_file.close()
    print(colored("PRIVATE KEY OK\n", "green"))

    return 0


def rsa_encrypt_credentials(message):
    """Encrypts a string with rsa and saves it in a credentials.cre file.

    Args:
        message (str) : string to encrypt with RSA

    Returns:
        int : 0
    """
    check_key_text = False
    while not check_key_text:
        key_text = input(
            "Enter the name of the file containing the recipient's RSA public key: "
        )
        if os.path.isfile(key_text) and key_text[-4:] == ".pem":
            check_key_text = True
            with open(key_text, "rb") as key_text:
                key_text = key_text.read()
            public_key = RSA.importKey(key_text)  # Imports the recipient's public key
            cipher = PKCS1_v1_5.new(public_key)
            message = message.encode()
            encrypted_bytes = cipher.encrypt(
                message
            )  # Encrypt decryption information with RSA
            with open("credentials.cre", "wb") as saved_credentials_file:
                saved_credentials_file.write(
                    encrypted_bytes
                )  # Write decryption information to the
                # credentials.cre file
                saved_credentials_file.close()
            print(
                colored(
                    "\nAll is good, You can send the encrypted file and the credentials.cre "
                    "file to your recipient",
                    "green",
                )
            )
        else:
            print(
                colored(
                    "\nFile doesnt not exist or the file extension is not .pem", "red"
                )
            )
    return 0


def rsa_decrypt_creds():
    """Decrypts a file encrypted with RSA


    Returns:
        str : decrypted string with RSA
    """
    check_private_key = False
    while not check_private_key:
        private_key = input(
            "Enter the name of the file containing your RSA private key: "
        )
        if os.path.isfile(private_key) and private_key[-4:] == ".pem":
            check_private_key = True
            with open(private_key, "rb") as private_key:
                private_key = private_key.read()
            check_credentials_encrypted = False
            while not check_credentials_encrypted:
                credentials_encrypted = input(
                    "Enter the name of the file containing the "
                    "decryption information "
                    "(.cre) : "
                )
                if (
                    os.path.isfile(credentials_encrypted)
                    and credentials_encrypted[-4:] == ".cre"
                ):
                    check_credentials_encrypted = True
                    with open(credentials_encrypted, "rb") as credentials_encrypted:
                        credentials_encrypted = credentials_encrypted.read()
                    private_key = RSA.importKey(
                        private_key
                    )  # Import the recipient's private
                    # key from the file
                    cipher = PKCS1_v1_5.new(private_key)
                    decrypted_credentials = cipher.decrypt(
                        credentials_encrypted, "ERROR"
                    )  # Decrypts information from
                    # .cre file
                    return str(decrypted_credentials.decode())
                else:
                    print(
                        colored(
                            "\nFile doesnt not exist or the file extension is not .cre",
                            "red",
                        )
                    )

        else:
            print(
                colored(
                    "\nFile doesnt not exist or the file extension is not .pem", "red"
                )
            )


def gen_password():
    """Generates a 16 character long random password containing numbers and letters


    Returns:
        bytes : the generated password
    """
    characters = string.ascii_letters + string.digits
    password = "".join(random.choice(characters) for i in range(16))
    password = bytes(password, "utf-8")
    return password


def aes_encrypt_data(file):
    """Encrypts a file with the AES method and saves in a file name_file.extension.enc

    Args:
        file (str) : file to encrypt with the AES method

    Returns:
        int : 0
    """
    name_file = file
    with open(file, "rb") as file:
        data_file = file.read()
    length = 16 - (len(data_file) % 16)  # Avoid block size error by adjusting length
    data_file += bytes([length]) * length
    password = gen_password()
    initialisation_vector = Random.new().read(
        BLOCK_SIZE
    )  # Generate 16 rand bytes for the IV
    iv_64 = base64.b64encode(initialisation_vector)
    aes = AES.new(password, AES.MODE_CBC, initialisation_vector)  # Generate AES method
    print("Encryption in progress ...\n")
    data_encrypt = aes.encrypt(data_file)  # Encrypt file data with AES
    with open(name_file + ".enc", "wb") as new_file:
        new_file.write(data_encrypt)
        new_file.close()
    print(colored("AES encryption done !", "green"))
    rsa_encrypt_credentials(str(iv_64.decode()) + "---" + password.decode())
    return 0


def aes_decrypt_data(file):
    """Decrypts a file with the AES method and saves in a file name_file.extension

    Args:
        file (str) : file to decrypt with the AES method

    Returns:
        int : 0
    """
    name_file = file.replace(".enc", "")
    with open(file, "rb") as file:
        data_file = file.read()
    credentials_string = rsa_decrypt_creds()  # Decrypt .cre data encrypt with RSA
    pos_separator = credentials_string.find("-")  # Separate the data from the .cre file
    initialisation_vector = credentials_string[0:pos_separator]
    password = credentials_string[pos_separator + 3 :].encode()
    initialisation_vector = base64.b64decode(initialisation_vector.encode())
    aes = AES.new(password, AES.MODE_CBC, initialisation_vector)  # Creating AES method
    print("Decryption in progress...")
    data_decrypt = aes.decrypt(data_file)  # Decrypt .enc file data
    with open(name_file, "wb") as new_file:
        new_file.write(data_decrypt)
        new_file.close()
    print(
        colored(
            "Decryption done...If your file cannot open, your credentials file is invalid",
            "green",
        )
    )
    return 0


def main():
    print("#############################################")
    print("########## ENCRYPT - DECRYPT AES ############")
    print("#############################################")
    print("\nWelcome to this tool developed by K3RM1T, what do you want to do?\n")
    print("   1: Encrypt a file")
    print("   2: Decrypt a file")
    print("   3: Generate an RSA key pair\n")
    result_choice = ""
    while result_choice != "1" or "2" or "3":
        result_choice = input("Enter your choice : ")
        if result_choice == "1":
            check_file_encrypt = False
            while not check_file_encrypt:
                file = input("Enter the name of the file to encrypt : ")
                if os.path.isfile(file):
                    check_file_encrypt = True
                    aes_encrypt_data(file)
                    sys.exit(0)
                else:
                    print(colored("\nFile doesnt not exist, try again", "red"))
        elif result_choice == "2":
            check_file_decrypt = False
            while not check_file_decrypt:
                file = input("Enter the name of the file to decrypt : ")
                if os.path.isfile(file) and file[-4:] == ".enc":
                    check_file_decrypt = True
                    aes_decrypt_data(file)
                    sys.exit(0)
                else:
                    print(
                        colored(
                            "\nFile doesnt not exist or the file extension is not .enc",
                            "red",
                        )
                    )
        elif result_choice == "3":
            rsa_generate_keys()
            sys.exit(0)
        print(colored("\nChoice error, try again", "red"))


if __name__ == "__main__":
    main()
