# Servidor (Usuario 1)
import Cifrado
import os
import flet as ft
import socket


class Servidor():
    def __init__(self,user):
        self.user = user
        Cifrado.generarCertificado(self.user)  
        
    def send_message_click(self,e):
        self.enviarDatos()
        
    def setupServidor(self,ventana):
        # Configuración del servidor
        host = 'localhost'  
        port = 12345       # Puerto de escucha

        # Crear un socket del servidor
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)  # Escuchar una conexión entrante

        print(f"Esperando una conexión entrante en {host}:{port}")

        # Aceptar la conexión entrante
        client_socket, addr = server_socket.accept()
        print(f"Conexión entrante desde {addr}")
        
        self.leerCertificados(client_socket)
        self.enviarCertificados(client_socket)
        
        verifCertUser= Cifrado.verificarCertificadosUser('certificados_recibidos_del_cli/certificate_AC_chain_recieved.pem',f'{self.user.nombreUsuario}_data/certificate_AC_chain.pem')
        if (verifCertUser):
            Cifrado.extraerClavePublica('certificados_recibidos_del_cli/certificate_client_recieved.pem', 'certificados_recibidos_del_cli/clave_publica_recibida.pem')
            
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
                    "/home/chat", [chat,chat_la],
                    horizontal_alignment=ft.MainAxisAlignment.END
                )
            )
        ventana.update()
        
        self.recibirDatos(client_socket, ventana)
            

        # Cerrar la conexión
        #client_socket.close()
        #server_socket.close()
        
    def enviarCertificados(self,socket):
        ruta = f"{self.user.nombreUsuario}_data"
        certificadosList = [f"certificate_{self.user.nombreUsuario}.pem", "certificate_AC2.pem", "certificate_AC_chain.pem"]
        for file_name in certificadosList:
            # Open the file in binary mode and read its contents
            with open(f"{ruta}/{file_name}", 'rb') as f:
                file_data = f.read()
            # Send the size of the file
            socket.sendall(len(file_data).to_bytes(4, 'big'))
            # Send the file data
            socket.sendall(file_data)
            
    def leerCertificados(self,socket):
        certificadosList = [f"certificate_client_recieved.pem", "certificate_AC2_recieved.pem","certificate_AC_chain_recieved.pem"]
        for file_name in certificadosList:
            # Receive the size of the file
            file_size = int.from_bytes(socket.recv(4), 'big')

            # Receive the file data
            file_data = socket.recv(file_size)

            # Write the file data to a file
            newpath = os.path.join(os.getcwd(), 'certificados_recibidos_del_cli')
            if not os.path.exists(newpath):
                os.makedirs(newpath)
            with open(os.path.join(newpath, file_name), 'wb') as f:
                f.write(file_data)
                        
    def recibirDatos(self,client_socket,ventana):
        newpath = os.path.join(os.getcwd(), 'temp')
        if not os.path.exists(newpath):
            os.makedirs(newpath)
        nombreArchivo = 'archivo_recibido_del_cliente.txt'
        
        with open(os.path.join(newpath, nombreArchivo), 'wb') as archivo:
            datos = client_socket.recv(1024)  
            archivo.write(datos)

        datosDescifrados = Cifrado.descifrarMensaje(os.path.join(newpath, nombreArchivo),f"{self.user.nombreUsuario}_data/private_key.pem")
        text = datosDescifrados.decode()
        self.chat.controls.append(ft.Text(text))
        ventana.update()
        if os.path.exists(os.path.join(newpath, nombreArchivo)):
            os.remove(os.path.join(newpath, nombreArchivo))
        
    
    def enviarDatos(self,text, socket, ventana):
        texto = text.value
        text.value = ""
        text.update()
        textoC = self.user.nombreUsuario + ": " + texto
        nombreArchivo = Cifrado.cifrarMensaje(textoC.encode(),"certificados_recibidos_del_cli/clave_publica_recibida.pem")
        with open(nombreArchivo, 'rb') as archivo:
            datos = archivo.read(1024)  # Lee datos del archivo en fragmentos
            socket.send(datos)
            
        texto = "tu: " + texto
        self.chat.controls.append(ft.Text(texto))
        ventana.update()
        if os.path.exists(nombreArchivo):
            os.remove(nombreArchivo)
        self.recibirDatos(socket,ventana)
        
        
        