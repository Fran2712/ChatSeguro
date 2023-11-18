from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA,ECC
from Crypto.Signature import DSS
import bcrypt
from OpenSSL import SSL as SSL
from OpenSSL import crypto
import os
import shutil

#passphrase AC1 = certifAC1
#passphrase AC2 = certifAC2
#passphrase A = certifUserA
#passphrase B = certifUserB
# A challenge password: Apass
def eliminarTemps():

    newpath = os.path.join(os.getcwd(), 'temp')
    if os.path.exists(newpath):
        for file in os.listdir(newpath):
            try:
                os.remove(file)
            except:
                pass
            
def deleteCerts():
    directory = os.getcwd()  # current directory
    for filename in os.listdir(directory):
        if filename.startswith('certificados_recibidos') and os.path.isdir(os.path.join(directory, filename)):
            try:
                shutil.rmtree(os.path.join(directory, filename))
            except:
                pass

    
def leerClave(filename):
    with open(filename, 'rb') as archivo:
        key = archivo.read(1024)  # Lee datos del archivo en fragmentos
    return key

def generarFirma(filename):
    with open(filename, 'rb') as archivo:
            msg = archivo.read(1024)
            key = ECC.import_key(open('privada.pem').read())
            h = SHA256.new(msg)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
    return signature

def verificarFirma(firma):
    key = ECC.import_key(open("receptorP.pem").read())
    #h = SHA256.new(received_message)
    verifier = DSS.new(key, 'fips-186-3')
    try:
       # verifier.verify(h, firma)
        print("The message is authentic.")
    except ValueError:
        print("The message is not authentic.")
    

def cifradoContraseña(contraseña):
    salt = bcrypt.gensalt()
    password = contraseña.encode('utf-8')
    hashed_password = bcrypt.hashpw(password, salt)
    return hashed_password

def verificarContraseña(contraseña, contraseñaHash):
    if bcrypt.checkpw(contraseña.encode('utf-8'), contraseñaHash):
        return True
    else:
        return False
    
def cifrarMensaje(msg, rutaClave):
    recipient_key = RSA.import_key(open(rutaClave).read())
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    print(ciphertext)
    print(tag)
    print(cipher.nonce)
    
    newpath = os.path.join(os.getcwd(), 'temp')
    if not os.path.exists(newpath):
        os.makedirs(newpath)
    nombreArchivo = "encrypted.bin"
    file_out = open(os.path.join(newpath, nombreArchivo), "wb")
    [ file_out.write(x) for x in (enc_session_key,cipher.nonce, tag, ciphertext) ]
    file_out.close()
    return os.path.join(newpath, nombreArchivo)
    

    
def descifrarMensaje(nombreArchivo,rutaClave):
    private_key = RSA.import_key(open(rutaClave).read())
    file_in = open(nombreArchivo, "rb")
    enc_session_key,nonce, tag, msg_cifrado = [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    file_in.close()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(msg_cifrado, tag)
    return data

def generarCertificado(user):
    ruta = f"{user.nombreUsuario}_data"
    newpath = os.path.join(os.getcwd(), ruta)
    
    if not os.path.exists(newpath):
        os.makedirs(newpath)
        
        passphrase = b"certifAC2"

        ca_key_file = open("AC2/privado/ca2key.pem", "rt")
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_file.read(),passphrase)
        
        ca_cert_file = open("AC2/ac2cert.pem", "rt")
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
        
        ca0_cert_file = open("AC1/ac1cert.pem", "rt")
        ca0_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca0_cert_file.read())

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()

        cert.get_subject().CN = "localhost"
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)  # Valid for 10 years
        cert.set_issuer(ca_cert.get_subject())

        cert.set_pubkey(key)
        cert.sign(ca_key, 'sha256')

        # Use the new folder path when writing the files
        with open(os.path.join(newpath, "private_key.pem"), "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8'))

        with open(os.path.join(newpath, f"certificate_{user.nombreUsuario}.pem"), "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
            
        with open(os.path.join(newpath, "certificate_AC2.pem"), "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca0_cert).decode('utf-8'))
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode('utf-8'))
            
        with open(os.path.join(newpath, "certificate_AC1.pem"), "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca0_cert).decode('utf-8'))
            
        with open(os.path.join(newpath, "certificate_AC_chain.pem"), "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca0_cert).decode('utf-8'))
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode('utf-8'))
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
            
    
def verificarCertificadosUser(cert_recibido, cert_AC2):

    # Load the certificate to be verified
    
    cert_file = open(cert_recibido, "rt")
    cert_to_verify = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())

    # Load the CA certificate
    ca_cert_file = open(cert_AC2, "rt")
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())

    # Create a certificate store and add the CA certificate
    store = crypto.X509Store()
    store.add_cert(ca_cert)

    # Create a X509StoreContext with the store and the certificate to be verified
    store_ctx = crypto.X509StoreContext(store, cert_to_verify)

    # Verify the certificate
    try:
        store_ctx.verify_certificate()
        print("Certificate verification successful.")
        return True
    except crypto.X509StoreContextError as e:
        print("Certificate verification failed. Error: ", e)
        return False
    
def extraerClavePublica(cert, claveArchivo):
    # Load the certificate
    ruta = os.path.join(os.getcwd(), cert)
    cert_file = open(ruta, "rt")
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())

    # Get the public key
    public_key = cert.get_pubkey()

    # To get it in PEM format
    pem_public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)
    with open(os.path.join(claveArchivo), "wt") as f:
        f.write(pem_public_key.decode('utf-8'))
        