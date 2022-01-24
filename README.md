This script allows the encryption of any type of file by mixing AES CBC encryption and RSA encryption.

Your file is encrypted in AES. AES encryption works with a password and an initialization vector (IV). Rather than storing these two values clearly in a file, I've put together a credentials.cre file which contains the password and the IV to decrypt your file. In order to secure this file and make the decryption exclusive to your recipient, the credentials.cre file is encrypted in RSA with your recipient's public key (4096)

Your recipient will have to decrypt the credentials.cre file with his RSA private key (4096)

<br>

##### **Informations :**

Dependencies : `pycryptodome, termcolor`

##### **Manual :**

1 : Install the packages necessary for the script to work
`pip3 install -r requirements.txt`

2 : Your encrypted file, your RSA private key (4096), and the credentials.cre file (only if you decrypt a file), the file to be decrypted must be in the current directory of the script.

###### **Generate the RSA key pair**

`To generate an RSA key pair, you just have to choose option number 3`

![Alt Text](https://media0.giphy.com/media/MJeEgCnNgKga75DgkM/giphy.gif?cid=790b7611147810cec698dbc66e9c97ba321f6312e10f630d&rid=giphy.gif&ct=g)
###### **Encryption**

`To encrypt a file, it must be in the current directory of the program. Then choose option number 1 of the program and follow the instructions`

![Alt Text](https://media1.giphy.com/media/w7Ww4fefQJuFTUQRL1/giphy.gif?cid=790b7611d0f6249508729e1a47ede541fd526da20f8b90c9&rid=giphy.gif&ct=g)

###### **Decryption**

`To decrypt a file, it must be in the program's current directory. Then choose program option number 2 and follow the instructions`

![Alt Text](https://media1.giphy.com/media/Z5y6gFgJFDJqHW92wf/giphy.gif?cid=790b7611e6e7778d1c5063e0c961354edba9c755b6f3df41&rid=giphy.gif&ct=g)
