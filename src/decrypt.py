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
    
