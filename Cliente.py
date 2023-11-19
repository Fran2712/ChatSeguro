# Cliente (Usuario 2)
import socket
import flet as ft
import Cifrado
import os


class Cliente():  
    def __init__(self,user):
        self.user = user
        Cifrado.generarCertificado(self.user)  
    
    def setupCliente(self,ventana):
        # Configuración del cliente
        host = 'localhost' 
        port = 12345        # Mismo puerto que el servidor

        # Crear un socket del cliente
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        
        self.enviarCertificados(client_socket)
        self.leerCertificados(client_socket)
        
        #Verificacion de Certificados y Extraccion de clave pública
        verifCertUser= Cifrado.verificarCertificadosUser('certificados_recibidos_del_serv/certificate_AC_chain_recieved.pem',f'{self.user.nombreUsuario}_data/certificate_AC_chain.pem')
        if (verifCertUser):
            Cifrado.extraerClavePublica('certificados_recibidos_del_serv/certificate_server_recieved.pem', 'certificados_recibidos_del_serv/clave_publica_recibida.pem')
        
        self.pb = ft.ProgressBar(width=400, color="amber", bgcolor="#eeeeee", visible=False) 
        txt = ft.TextField(
            hint_text="Mensaje",
            autofocus=True,
            shift_enter=True,
            min_lines=1,
            max_lines=5,
            filled=True,
            expand=True,
            on_submit= lambda x: self.enviarDatos(txt, client_socket, ventana)
        )
        chat = ft.ListView(
            expand=True,
            spacing=10,
            auto_scroll=True
        )
        self.chat = chat
        
        chat_la = ft.Row(
            controls=[
                txt, ft.IconButton(
                    icon=ft.icons.SEND_ROUNDED,
                    tooltip="Send message",
                    on_click=lambda x: self.enviarDatos(txt, client_socket, ventana)
                )
            ]   
        )
        ventana.views.append(
                ft.View(
                    "/home/chat", [chat,chat_la,self.pb],
                    horizontal_alignment=ft.MainAxisAlignment.END
                )
            )
        ventana.update()
        
        # Cerrar la conexión
        #client_socket.close()
      
    def enviarCertificados(self,socket):
        ruta = f"{self.user.nombreUsuario}_data"
        certificadosList = [f"certificate_{self.user.nombreUsuario}.pem", "certificate_AC2.pem","certificate_AC_chain.pem"] # Lista de los certificados a enviar
        for file_name in certificadosList:
            # Abre el archivo en modo binario y lee su contenido
            with open(f"{ruta}/{file_name}", 'rb') as f:
                file_data = f.read()
            # Envia el tamaño del archivo
            socket.sendall(len(file_data).to_bytes(4, 'big'))
            # Envia los datos del archivo
            socket.sendall(file_data)
            
    def leerCertificados(self,socket):
        ruta = f"{self.user.nombreUsuario}_data"
        certificadosList = [f"certificate_server_recieved.pem", "certificate_AC2_recieved.pem","certificate_AC_chain_recieved.pem"]
        for file_name in certificadosList:
            # Recibe el tamaño del archivo
            file_size = int.from_bytes(socket.recv(4), 'big')
            # Recibe los datos del archivo
            file_data = socket.recv(file_size)
            # Escribe los datos en un archivo
            newpath = os.path.join(os.getcwd(), 'certificados_recibidos_del_serv')
            if not os.path.exists(newpath):
                os.makedirs(newpath)
            with open(os.path.join(newpath, file_name), 'wb') as f:
                f.write(file_data)
      
    def recibirDatos(self,client_socket,ventana):
        newpath = os.path.join(os.getcwd(), 'temp')
        if not os.path.exists(newpath):
            os.makedirs(newpath)
        nombreArchivo = 'archivo_recibido_del_servidor.txt'
        listaArchivos = ['archivo_recibido_del_servidor.txt','firma_recibida_del_servidor.txt'] 
        self.pb.visible = True
        ventana.update()
        for file_name in listaArchivos:
            # Recibe el tamaño del archivo
            file_size = int.from_bytes(client_socket.recv(4), 'big')
            # Recibe los datos del archivo
            file_data = client_socket.recv(file_size)
            # Escribe los datos en un archivo
            newpath = os.path.join(os.getcwd(), 'temp')
            if not os.path.exists(newpath):
                os.makedirs(newpath)
            with open(os.path.join(newpath, file_name), 'wb') as f:
                f.write(file_data)
        datosDescifrados = Cifrado.descifrarMensaje(os.path.join(newpath, nombreArchivo),f"{self.user.nombreUsuario}_data/private_key.pem")
        verif = Cifrado.verificarFirma(datosDescifrados, os.path.join(newpath, 'firma_recibida_del_servidor.txt'), 'certificados_recibidos_del_serv/clave_publica_recibida.pem')
        # Si la verificacion es correcta 
        if verif:
            text = datosDescifrados.decode()
            self.chat.controls.append(ft.Text(text))
            self.pb.visible = False
            ventana.update()
            for archivo in listaArchivos:
                if os.path.exists(os.path.join(newpath, archivo)):
                    os.remove(os.path.join(newpath, archivo))
        else:
            print("ERROR, FALLO DE VERIFICACION DE FIRMA")

        
    def enviarDatos(self,text, socket, ventana):
        texto = text.value
        text.value = ""
        text.update()
        textoC = self.user.nombreUsuario+ ": " + texto
        
        listaArchivos = []
        nombreArchivo = Cifrado.cifrarMensaje(textoC.encode(),"certificados_recibidos_del_serv/clave_publica_recibida.pem")
        listaArchivos.append(nombreArchivo)
        nombreFirma = Cifrado.firmarMensaje(textoC.encode(),f"{self.user.nombreUsuario}_data/private_key.pem")
        listaArchivos.append(nombreFirma)
        
        for file_name in listaArchivos:
            # Abre el archivo en modo binario y lee su contenido
            with open(file_name, 'rb') as f:
                file_data = f.read(1024)
            # Envia el tamaño del archivo
            socket.sendall(len(file_data).to_bytes(4, 'big'))
            # Envia los datos del archivo
            socket.sendall(file_data)
        
        texto = "tu: " + texto
        self.chat.controls.append(ft.Text(texto))
        ventana.update()
        if os.path.exists(nombreArchivo):
            os.remove(nombreArchivo)
        self.recibirDatos(socket,ventana)
        