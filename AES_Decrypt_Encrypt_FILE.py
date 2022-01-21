import base64
import string
import random
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

BLOCK_SIZE = 16  # Constante pour définir la taille de blocs pour le fonctionnement d'AES


def rsa_generate_keys():
    """Generate RSA KEY PAIR.

    Returns:
            int : 0
    """
    key = RSA.generate(4096)  # Génération de la paire de clé rsa
    pubKey = key.public_key().exportKey('PEM').decode()
    publicKeyFile = open('publicKey.pem', 'w')
    publicKeyFile.write(pubKey)  # Ecriture de la clé publique dans le fichier publicKey.pem
    publicKeyFile.close()
    print(f'CLE PUBLIQUE OK\n')

    privKey = key.exportKey('PEM').decode()
    privateKeyFile = open('privateKey.pem', 'w')
    privateKeyFile.write(privKey)  # Ecriture de la clé privé dans le fichier publicKey.pem
    privateKeyFile.close()
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
    public_key = RSA.importKey(key_text)  # Importe la clé publique du destinataire
    cipher = PKCS1_v1_5.new(public_key)
    message = message.encode()
    encrypted_bytes = cipher.encrypt(message)  # Chiffre les informations de déchiffrement avec RSA
    saved_creds_file = open("credentials.cre", 'wb')
    saved_creds_file.write(encrypted_bytes)  # Ecrit les informations de déchiffrement dans le fichier credentials.cre
    saved_creds_file.close()
    print(f'All is good, You can send the encrypted file and the credentials.cre file to your recipient')
    return 0


def rsa_decrypt_creds():
    """Decrypts a file encrypted with RSA


        Returns:
            str : decrypted string with RSA
    """
    key_priv = open(input("Enter the name of the file containing your RSA private key: "), "rb").read()
    creds_encrypted = open(input("Enter the name of the file containing the decryption information (.cre) : "),
                           'rb').read()
    private_key = RSA.importKey(key_priv)  # Importe la clé privé du destinataire du fichier
    cipher = PKCS1_v1_5.new(private_key)
    decrypted_credentials = cipher.decrypt(creds_encrypted, "ERROR")  # Déchiffre les informations du fichier cre"
    return str(decrypted_credentials.decode())  # Retourne les informations déchiffrées


def gen_password():
    """Generates a 16 character long random password containing numbers and letters


        Returns:
            bytes : the generated password
    """
    characters = string.ascii_letters + string.digits  # Désigne caractères dans mdp, ici lettres et chiffres
    password = ''.join(random.choice(characters) for i in range(16))  # Génère un mot de passe de 16 caractères
    password = bytes(password, 'utf-8')  # Converti en bytes le mot de passe
    return password  # Retourne le mot de passe


def aes_encrypt_data(file):
    """Encrypts a file with the AES method and saves in a file name_file.extension.enc

        Args:
            file (str) : file to encrypt with the AES method

        Returns:
            int : 0
    """
    name_file = file
    file = open(file, "rb")  # Ouvre le fichier à chiffrer
    data_file = file.read()  # Lis le fichier à chiffrer
    length = 16 - (len(data_file) % 16)  # Permet d'éviter les erreur de taille de bloc en ajustant la longueur"
    data_file += bytes([length]) * length
    password = gen_password()  # Génère un mot de passe pour la méthode AES
    IV = Random.new().read(BLOCK_SIZE)  # Génère 16 bytes random pour le vecteur d'initialisation (IV)
    IV64 = base64.b64encode(IV)  # Encode en base64 l'IV
    aes = AES.new(password, AES.MODE_CBC, IV)  # Génère une méthode AES grace au mdp et à l'IV
    print(f'Encryption in progress ...\n')
    data_encrypt = aes.encrypt(data_file)  # Chiffre les données du fichier avec AES
    new_file = open(name_file + '.enc', 'wb')
    new_file.write(data_encrypt)  # Ecrit les données chiffrés dans une fichier .enc
    new_file.close()
    print(f'AES encryption done !')
    credentials_rsa_encrypted = rsa_encrypt_creds(str(IV64.decode()) + "---" + password.decode())  # Sépare IV et mdp
    return 0


def aes_decrypt_data(file):
    """Decrypts a file with the AES method and saves in a file name_file.extension

        Args:
            file (str) : file to decrypt with the AES method

        Returns:
            int : 0
    """
    name_file = file.replace(".enc", "")
    file = open(file, "rb")  # Ouvre le fichier chiffré .enc
    data_file = file.read()  # Lis les données du fichier
    credentials_string = rsa_decrypt_creds()  # Déchiffre les données du .cre chiffré avec RSA
    pos_separator = credentials_string.find("-")  # Sépare les données du fichier .cre en un mdp et un IV
    IV = credentials_string[0:pos_separator]  # Sépare les données du fichier .cre en un mdp et un IV
    password = credentials_string[pos_separator + 3:]  # Sépare les données du fichier .cre en un mdp et un IV
    password = password.encode()  # Encode le mdp pour qu'il soit reconnu comme un byte
    IV = base64.b64decode(IV.encode())  # Decode l'IV de la base64 et l'encode en byte
    aes = AES.new(password, AES.MODE_CBC, IV)  # Création d'une méthode d'AES avec le mdp et L'IV
    print(f'Decryption in progress...')
    data_decrypt = aes.decrypt(data_file)  # Déchiffre les données du fichier .enc
    new_file = open(name_file, 'wb')
    new_file.write(data_decrypt)  # Enregistre le fichier déchiffré
    new_file.close()
    print(f'Decryption done...If your file cannot open, your credentials file is invalid')
    return 0


print("#############################################")
print("########## ENCRYPT - DECRYPT AES ############")
print("#############################################")
print(f'\nWelcome to this tool developed by K3RM1T, what do you want to do?\n')
print(f'   1: Encrypt a file')
print(f'   2: Decrypt a file')
print(f'   3: Generate an RSA key pair\n')
result_choice = int(input("Enter your choice : "))
if result_choice == 1:
    aes_encrypt_data(input("Enter the name of the file to encrypt : "))
if result_choice == 2:
    aes_decrypt_data(input("Enter the name of the file to decrypt : "))
if result_choice == 3:
    rsa_generate_keys()
