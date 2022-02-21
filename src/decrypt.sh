#!/bin/bash


while [[ -f "../toDecrypt/toDecrypt.txt" ]]; do

	python3 ../src/decrypt.py ../toDecrypt/toDecrypt.txt ../Decrypted/Decrypted.txt

	rm ../toDecrypt/toDecrypt.txt

	sleep 2

done
