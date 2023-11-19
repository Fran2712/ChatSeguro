import flet as ft
from ConexionBD import Conexion
from Usuario import Usuario
from Servidor import Servidor
from Cliente import Cliente
from Cifrado import eliminarTemps,deleteCerts

   
def main(page):
    eliminarTemps()
    deleteCerts()
    connBD = Conexion('chatdb.db')
    connBD.crearTablas()
    
    def creacionUsuario(nombreUsuario, contraseña):
        usuario = Usuario(nombreUsuario, contraseña)
        return usuario

    def open_home(e):
        nUsuario = usuario.value
        nPass = contraseña.value
        user = creacionUsuario(nUsuario,nPass)
        select = connBD.buscarUsuario(user)
        if select is None:
            print("Usuario no existe")
            connBD.guardarUsuario(user)
        elif select == False:
            print("Contraseña incorrecta") # TODO maximo intentos, otra oprtunidad
        else:
            page.go("/home")
            page.update()
            
    
    
    def setupServidor(e):
        page.go("/home/chat")
        page.update()
        nUsuario = usuario.value
        nPass = contraseña.value
        user = creacionUsuario(nUsuario,nPass)
        a = Servidor(user)
        a.setupServidor(page)
        
    def setupCliente(e):
        page.go("/home/chat")
        page.update()
        nUsuario = usuario.value
        nPass = contraseña.value
        user = creacionUsuario(nUsuario,nPass)
        b = Cliente(user)
        b.setupCliente(page)
    
    page.window_width = 500
    page.window_height = 500
    page.window_resizable = False
    page.title = "Chat Seguro"
    
    titulo = ft.Row(
        controls=[
            ft.Text(
                text_align=ft.TextAlign.CENTER,
                value=f"Iniciar Sesión",
                size=55,
                weight=ft.FontWeight.W_100,
            ),
        ],
        alignment= ft.MainAxisAlignment.CENTER
    )
    
    usuario = ft.TextField(label="Usuario", autofocus=True)
    contraseña = ft.TextField(label="Contraseña", password=True, can_reveal_password=True)
    
    botonera = ft.Row(
        controls=[
            ft.FilledTonalButton(
                text="Registrarse",
                #on_click = on_click=open_mail_settings,
                width=150
            ),
            ft.FilledButton(
                text="Entrar",
                on_click=open_home,
                width=150
            )
        ],
        alignment= ft.MainAxisAlignment.CENTER,
        
    )

    
    page.add(
        titulo,
        usuario,
        contraseña,
        botonera
    )
    
    def route_change(e):
        if page.route == "/home":
            page.views.append(
                ft.View(
                    "/home",
                    [
                        ft.FilledButton(
                            text="Crear chat",
                            on_click = setupServidor,
                            width=150
                        ),
                        ft.FilledButton(
                            text="Unirse a chat",
                            on_click = setupCliente,
                            width=150
                        )
                    ],
                    vertical_alignment= ft.MainAxisAlignment.SPACE_EVENLY,
                    horizontal_alignment = ft.CrossAxisAlignment.CENTER
                )
            )
            
        page.update()
        
    pb = ft.ProgressBar(width=400, color="amber", bgcolor="#eeeeee")
    
    page.on_route_change = route_change
    



if __name__=="__main__": 
    ft.app(target=main)