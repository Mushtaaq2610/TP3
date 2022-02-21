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
    
