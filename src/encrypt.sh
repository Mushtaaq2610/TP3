#!/bin/bash


while [[ -f "../toCrypt/toCrypt.txt" ]]; do

	python3 ../src/crypt.py ../toCrypt/toCrypt.txt ../toDecrypt/toDecrypt.txt

	rm ../toCrypt/toCrypt.txt

	sleep 2

done


