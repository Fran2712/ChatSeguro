import sqlite3
import Usuario
import Cifrado


class Conexion:
    
    def __init__(self, nombreDB):
        self.connection = sqlite3.connect(nombreDB)
        self.nombreDB = nombreDB
        
    def crearTablas(self):
        con = sqlite3.connect(self.nombreDB)
        cursor = self.connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Usuarios (
                nombre TEXT,
                contrasena TEXT,
                UNIQUE(nombre)
            )
        ''')
        cursor.close()
        con.close()
        
    
    def guardarUsuario(self, user):
        con = sqlite3.connect(self.nombreDB)
        cursor = con.cursor()
        contrasenaHash = Cifrado.cifradoContraseña(user.contrasenaUsuario)
        cursor.execute("INSERT INTO Usuarios (nombre, contrasena) VALUES (?, ?)", (user.nombreUsuario, contrasenaHash))
        con.commit()
        cursor.close()
        con.close()
        
    def buscarUsuario(self, user):
        con= sqlite3.connect(self.nombreDB)
        cursor = con.cursor()
        cursor.execute("SELECT nombre, contrasena FROM usuarios WHERE nombre = ?", (user.nombreUsuario,))
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            return None
        else:
            nombre, contraseña = row
            verif = Cifrado.verificarContraseña(user.contrasenaUsuario, contraseña)
            if verif:
                con.close()
                return True
            else:
                con.close()
                return False
        
        
    
        
    def acabarConexion(self):
        self.connection.close()