from Crypto.PublicKey import RSA

key = RSA.generate(1024)


#afficher ses clés:
k = key.exportKey('PEM')
p = key.publickey().exportKey('PEM')

#sauvegarder ses clés dans des fichiers:
with open('private.pem','w') as kf:
	kf.write(k.decode())
	kf.close()

with open('public.pem','w') as pf:
	pf.write(p.decode())
	pf.close()
