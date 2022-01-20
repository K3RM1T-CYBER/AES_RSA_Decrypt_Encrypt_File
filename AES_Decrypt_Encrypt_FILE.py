import base64
import string
import random
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

BLOCK_SIZE = 16


def rsa_generate_keys():
    key = RSA.generate(4096)
    pubKey = key.public_key().exportKey('PEM').decode()
    publicKeyFile = open('publicKey.pem', 'w')
    publicKeyFile.write(pubKey)
    publicKeyFile.close()
    print("CLE PUBLIQUE OK\n")

    privKey = key.exportKey('PEM').decode()
    privateKeyFile = open('privateKey.pem', 'w')
    privateKeyFile.write(privKey)
    privateKeyFile.close()
    print("CLE PRIVÉE OK\n")

    return 0


def rsa_encrypt_creds(message):
    key_text = open(input("Enter the name of the file containing the recipient's RSA public key: "), "rb").read()
    public_key = RSA.importKey(key_text)
    cipher = PKCS1_v1_5.new(public_key)
    message = message.encode()
    encrypted_bytes = cipher.encrypt(message)
    saved_creds_file = open("credentials.cre", 'wb')
    saved_creds_file.write(encrypted_bytes)
    saved_creds_file.close()
    print("Encryption done ! You can send the encrypted file and the credentials.cre file to your recipient")
    return 0


def rsa_decrypt_creds():
    key_priv = open(input("Enter the name of the file containing your RSA private key: "), "rb").read()
    creds_encrypted = open(input("Enter the name of the file containing the decryption information (.cre) : "),
                           'rb').read()
    private_key = RSA.importKey(key_priv)
    cipher = PKCS1_v1_5.new(private_key)
    decrypted_credentials = cipher.decrypt(creds_encrypted, "ERROR")
    return str(decrypted_credentials.decode())


def gen_password():
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for i in range(16))
    password = bytes(password, 'utf-8')
    return password


def aes_encrypt_data(file):
    name_file = file
    file = open(file, "rb")
    data_file = file.read()
    length = 16 - (len(data_file) % 16)
    data_file += bytes([length]) * length
    password = gen_password()
    IV = Random.new().read(BLOCK_SIZE)
    IV64 = base64.b64encode(IV)
    aes = AES.new(password, AES.MODE_CBC, IV)
    print("Encryption in progress ...\n")
    data_encrypt = aes.encrypt(data_file)
    new_file = open(name_file + '.enc', 'wb')
    new_file.write(data_encrypt)
    new_file.close()
    credentials_rsa_encrypted = rsa_encrypt_creds(str(IV64.decode()) + "---" + password.decode())
    return 0


def aes_decrypt_data(file):
    name_file = file.replace(".enc", "")
    file = open(file, "rb")
    data_file = file.read()
    credentials_string = rsa_decrypt_creds()
    pos_separator = credentials_string.find("-")
    IV = credentials_string[0:pos_separator]
    password = credentials_string[pos_separator + 3:]
    password = password.encode()
    IV = base64.b64decode(IV.encode())
    aes = AES.new(password, AES.MODE_CBC, IV)
    print('Decryption in progress...')
    data_decrypt = aes.decrypt(data_file)
    new_file = open(name_file, 'wb')
    new_file.write(data_decrypt)
    new_file.close()
    print("Decryption done...If your file cannot open, your credentials file is invalid")
    return 0


print("#############################################")
print("########## ENCRYPT - DECRYPT AES ############")
print("#############################################")
print("\nWelcome to this tool developed by K3RM1T, what do you want to do?\n")
print("   1: Encrypt a file")
print("   2: Decrypt a file")
print("   3: Generate an RSA key pair\n")
result_choice = int(input("Enter your choice : "))
if result_choice == 1:
    aes_encrypt_data(input("Enter the name of the file to encrypt : "))

if result_choice == 2:
    aes_decrypt_data(input("Enter the name of the file to decrypt : "))
if result_choice == 3:
    rsa_generate_keys()
