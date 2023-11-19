from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA,ECC
from Crypto.Signature import pkcs1_15
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

# Funcion que elimina los archivos temporales
def eliminarTemps():
    newpath = os.path.join(os.getcwd(), 'temp')
    if os.path.exists(newpath):
        for file in os.listdir(newpath):
            file_path = os.path.join(newpath, file)
            try:
                os.remove(file_path)
            except (Exception, OSError) as e:
                print("Error while deleting file : ", file_path, e)
                
# Funcion que eliminas los certificados  
def deleteCerts():
    directory = os.getcwd()
    for filename in os.listdir(directory):
        if filename.startswith('certificados_recibidos') and os.path.isdir(os.path.join(directory, filename)):
            try:
                shutil.rmtree(os.path.join(directory, filename))
            except:
                pass
# Funcion que Hashea la contraseña
def cifradoContraseña(contraseña):
    salt = bcrypt.gensalt()
    password = contraseña.encode('utf-8')
    hashed_password = bcrypt.hashpw(password, salt)
    return hashed_password
# Funcion que verifica si la contraseña introducida concuerda con el hash recibido por parametro
def verificarContraseña(contraseña, contraseñaHash):
    if bcrypt.checkpw(contraseña.encode('utf-8'), contraseñaHash):
        return True
    else:
        return False
# Funcion que cifra un mensaje (AES) y escribe el mensaje cifrado,nonce y tag en temp/encrypted.bin
def cifrarMensaje(msg, rutaClave):
    recipient_key = RSA.import_key(open(rutaClave).read()) # importa la clave publica
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

# Funcion que firma un mensaje con la clave privada y escribe la firma en temp/signature.bin 
def firmarMensaje(msg, clave_privada_ruta):
    hash_obj = SHA256.new(msg)
    private_key_obj = RSA.import_key(open(clave_privada_ruta).read())
    signature = pkcs1_15.new(private_key_obj).sign(hash_obj)

    newpath = os.path.join(os.getcwd(), 'temp')
    if not os.path.exists(newpath):
        os.makedirs(newpath)
    nombreArchivo = "signature.bin"
    file_out = open(os.path.join(newpath, nombreArchivo), "wb")
    file_out.write(signature)
    file_out.close()
    return os.path.join(newpath, nombreArchivo)

# Funcion que verifica la firma del mensaje con la clave publica recibida
def verificarFirma(msg, firma, clave_publica_ruta):
    with open(firma, 'rb') as f:
                file_data = f.read()
    public_key_obj = RSA.import_key(open(clave_publica_ruta).read())
    hash_obj = SHA256.new(msg)
    try:
        pkcs1_15.new(public_key_obj).verify(hash_obj, file_data)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False
    
# Funcion que descifra el mensaje, recibe la ruta del archivo que contiene el mensaje y la ruta de la clave
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

# Funcion que genrea un certificado siguiendo la PKI de la aplicacion
def generarCertificado(user):
    ruta = f"{user.nombreUsuario}_data"
    newpath = os.path.join(os.getcwd(), ruta)
    
    if not os.path.exists(newpath):
        os.makedirs(newpath)
        
        passphrase = b"certifAC2"

        ca_key_file = open("AC2/privado/ca2key.pem", "rt") # Clave privada de la AC2
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_file.read(),passphrase)
        
        ca_cert_file = open("AC2/ac2cert.pem", "rt") #certificado de AC2
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
        
        ca0_cert_file = open("AC1/ac1cert.pem", "rt") # certificado de AC1
        ca0_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca0_cert_file.read())

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048) #Genera una clave privada RSA de 2048 bits
        cert = crypto.X509()
        # Detalles del certificado 
        cert.get_subject().CN = "localhost"
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)  # Valid for 10 years
        cert.set_issuer(ca_cert.get_subject())

        cert.set_pubkey(key)
        cert.sign(ca_key, 'sha256')
        # Escribe los certificados en la carpeta destinada para el usuario actual 
        with open(os.path.join(newpath, "private_key.pem"), "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')) # Escribe la clave privada RSA

        with open(os.path.join(newpath, f"certificate_{user.nombreUsuario}.pem"), "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))# Escribe el certificado del usuario actual
            
        with open(os.path.join(newpath, "certificate_AC2.pem"), "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca0_cert).decode('utf-8'))
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode('utf-8'))# Escribe la cadena de certificacion de AC2
            
        with open(os.path.join(newpath, "certificate_AC1.pem"), "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca0_cert).decode('utf-8'))# escribe el certificado de AC1
            
        with open(os.path.join(newpath, "certificate_AC_chain.pem"), "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca0_cert).decode('utf-8'))
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode('utf-8'))
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))# Escribe la cadena de certificacion del usuario actual
            

# Funcion que verifica los certificados
def verificarCertificadosUser(cert_recibido, cert_AC2):
    # Abre el certificado recibido
    cert_file = open(cert_recibido, "rt")
    cert_to_verify = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
    # Abre el certificado de la AC2
    ca_cert_file = open(cert_AC2, "rt")
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
    store = crypto.X509Store()
    store.add_cert(ca_cert)
    store_ctx = crypto.X509StoreContext(store, cert_to_verify)
    # Verifica el certificado recibido
    try:
        store_ctx.verify_certificate()
        print("Certificate verification successful.")
        return True
    except crypto.X509StoreContextError as e:
        print("Certificate verification failed. Error: ", e)
        return False

# Funcion que Esxtrae la clave publica del certificado recibido 
def extraerClavePublica(cert, claveArchivo):
    # Abre el certificado recibido
    ruta = os.path.join(os.getcwd(), cert)
    cert_file = open(ruta, "rt")
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())

    # Extrae la clave publica
    public_key = cert.get_pubkey()

    # La guarda en la ruta especificada con archivo .PEM
    pem_public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)
    with open(os.path.join(claveArchivo), "wt") as f:
        f.write(pem_public_key.decode('utf-8'))
        