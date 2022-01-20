This script allows the encryption of any type of file by mixing AES CBC encryption and RSA encryption.

Your file is encrypted in AES. AES encryption works with a password and an initialization vector (IV). Rather than storing these two values clearly in a file, I've put together a credentials.cre file which contains the password and the IV to decrypt your file. In order to secure this file and make the decryption exclusive to your recipient, the credentials.cre file is encrypted in RSA with your recipient's public key (4096)

Your recipient will have to decrypt the credentials.cre file with his RSA private key (4096)

##### **Manual :**

1 : Install the packages necessary for the script to work
`pip3 install -r requirements.txt`

2 : Your encrypted file, your RSA private key (4096), and the credentials.cre file (only if you decrypt a file), the file to be decrypted must be in the current directory of the script.

###### **Generate the RSA key pair**

`To generate an RSA key pair, you just have to choose option number 3`

###### **Encryption**

`To encrypt a file, it must be in the current directory of the program. Then choose option number 1 of the program and follow the instructions`

###### **Decryption**

`To decrypt a file, it must be in the program's current directory. Then choose program option number 2 and follow the instructions`