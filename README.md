###TP encrypt & decrypt

## Faire un git clone
sh
git clone https://github.com/Mushtaaq2610/TD_Crypted.git


## Installer le module Crypto

sudo apt-get install python3-crypto


## Creer 4 dossiers:
- Resources
- Src
- Results
- Services

## Creer 2 fichier services:
sh 
encrypt.service
decrypt.service

## encrypt.service
[Unit]
Description=Encryption
After=network-online.target

[Service]
Type=simple
ExecStart=/home/client/Documents/GSLW/TP3/src/crypt.sh

[Install]
WantedBy=multi-user.target

## decrypt.service
sh
[Unit]
Description=Decryption
After=network-online.target

[Service]
Type=simple
ExecStart=/home/client/Documents/GSLW/TP3/src/decrypt.sh

[Install]
WantedBy=multi-user.target

## Dans le dossier resources, il faut creer un fichier text qui contient un mot:
sh
les codes suivants c'est pour creer le fichier text:
nano toto.txt 

## Folder Src :
on doit creer 3 fichier python:

- crypt.py
- decrypt.py
- generate.py

## Code pour le fichier crypt.py
sh
from Crypto.PublicKey import RSA

import os


def encrypted_func(filename,fileloc):


    with open('.public.pem','r') as fp:

        pub = fp.read()

        fp.close()
            


            
    public = RSA.importKey(pub)


    #chiffrage
    public_key = public.publickey()

        	
    with open(filename, "rb") as file:

        #read all file data
        
        file_data = file.read()
        

    #encrypt data
    encrypted_data = public_key.encrypt(file_data,len(file_data))
    print(encrypted_data)
   
    #write the encrypted file
    with open(fileloc, "wb") as file:

        file.write(encrypted_data[0])


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="Simple File Encryptor Script")
    
    parser.add_argument("filen", help="File to encrypt")

    parser.add_argument("fileloc", help="File where to store encrypt file")


    args = parser.parse_args()
    
    filen = args.filen
    fileloc = args.fileloc

    encrypted_func(filen,fileloc)


## code pour le fichier decrypt.py:
sh
from Crypto.PublicKey import RSA

import os


def decrypt_func(filename,fileloc):


    with open('.private.pem','r') as fp:

        priv = fp.read()

        fp.close()
            


            
    privat = RSA.importKey(priv) 
    

        	
    with open(filename, "rb") as file:

        #read all file data
        
        file_data = file.read()
        

    #encrypt data
    decrypted_data = privat.decrypt(file_data)
    decrypted_data = decrypted_data.decode('utf-8')
    print(decrypted_data)
   
    #write the encrypted file
    with open(fileloc, "w") as file:

        file.write(decrypted_data)


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="Simple File Encryptor Script")
    
    parser.add_argument("filen", help="File to encrypt")

    parser.add_argument("fileloc", help="File to decrypt")

    args = parser.parse_args()
    
    filen = args.filen

    fileloc = args.fileloc
    

    decrypt_func(filen,fileloc)
    
## code pour le fichier generate.py
sh
from Crypto.PublicKey import RSA

key = RSA.generate(1024)


#afficher ses clés:
sh
k = key.exportKey('PEM')
p = key.publickey().exportKey('PEM')

#sauvegarder ses clés dans des fichiers:
sh
with open('private.pem','w') as kf:
	kf.write(k.decode())
	kf.close()

with open('public.pem','w') as pf:
	pf.write(p.decode())
	pf.close()
	
 
## Donner droit d'execution aux fichiers .py  
sh
chmod +x generate.py
chmod +x crypt.py
chmod +x decrypt.py
  
## Pour que le fichier crypt, il faut inserez les codes suivants:
sh
python3 ../resources/toto.txt ../results/toto_crypted.txt

Ensuite le fichier toto.txt sera crypte et envoyera la message dans le dossier results sous le nom toto_crypted.txt
  
## decryption
sh
python3 ../results/toto_crypted.txt ../results/toto_decrypted.txt

Ensuite le fichier toto_crypted.txt sera decrypte et envoyera la message dans le dossier results sous un le nom toto_decrypted.txt


### Creer 4 autres dossiers:
sh
toCrypt, Crypted, toDecrypt, Decrypted

## Creer une fichier install et uninstall

##install.sh 
sh
#!/bin/bash

install_service()
{
#get service name
service_name=$(echo "$1" | cut -d "." -f 1)
#get script name
script_name="${service_name}.sh"

#copy service file if not exists
if [ ! -f /etc/systemd/system/$service_name ]
then
	sudo cp $2/service/$1 /etc/systemd/system/
else
	echo "$service_name file already exist, please check"
fi


#copy script if not exists
if [ ! -f /bin/$script_name ]
then
	sudo cp $2/src/$script_name /bin/
else
	echo "$script_name already exists, please check"
fi

#create log folder if not exists
if [ ! -d /var/log/$service_name ]
then
	sudo mkdir /var/log/$service_name
else
	echo "log folder already exists"
fi

#activating the service
sudo systemctl enable $1
#start the service
sudo systemctl start $1

}


INSTALL_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


install_service encrypt.service $INSTALL_DIR
install_service decrypt.service $INSTALL_DIR

## Uninstall.sh
sh

#!/bin/bash

uninstall_daemon()
{
#stopping service
sudo systemctl stop $1
#disabling service
sudo systemctl disable $1

#check if service file exists then delete it
if [ -f /etc/systemd/system/$1 ]
then
	sudo rm -rf /etc/systemd/system/$1
else
	echo "/etc/systemd/system/$1 does not exist"
fi

#check if log folder exists then deleted it
service_name=$(echo $1 | cut -d "." -f 1)
if [ -d /var/log/$service_name ]
then
	sudo rm -rf /var/log/$service_name
else
	echo "/var/log/$service_name not found"
fi

#check if binary exists then delete it
script_name="${service_name}.sh"
if [ -f /bin/$script_name ]
then
        sudo rm -rf /bin/$script_name
else
        echo "/bin/$script_name does not exist"
fi

}


uninstall_daemon encrypt.service
uninstall_daemon decrypt.service

### Fichier Install

Le fichier install permettra de crypter et decrypter automatiquement

### Fichier Uninstall

Le fichier uninstall permettra desinstaller le project.

### Droit d'execution au fichier install et uninstall
sh
chmod +x install.sh
chmod +x uninstall.sh

## Executer les fichiers
sh
./install.sh
./uninstall.sh
