import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, make_response
import sqlite3, webbrowser, threading
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Cargar las variables de entorno desde el archivo superkey.env
load_dotenv('superkey.env')

app = Flask(__name__)
app.secret_key = 'superkey'

def init_sqlite_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Crear tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    # Crear tabla de carritos con la columna cantidad
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS carts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            peluche_id INTEGER,
            cantidad INTEGER DEFAULT 1,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    #CREADOR DE ROL DE ADMIN
    username = "admin"
    admin_password = os.getenv('ADMIN_PASSWORD')
    if not admin_password:
        raise ValueError("La variable de entorno ADMIN_PASSWORD no está definida")
    password_admin = generate_password_hash(admin_password)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user2 = cursor.fetchone()
    if user2:
        print("El nombre de usuario ya existe. No se puede insertar.")
    else:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_admin))
        conn.commit()
        print("Usuario insertado exitosamente.")
    conn.close()

init_sqlite_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def no_cache(view):
    @wraps(view)
    def no_cache_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache_view

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register/', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        try:
            conn = sqlite3.connect('database.db')
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return redirect(url_for('user_exists'))
    return render_template('register.html')

@app.route('/user_exists/')
def user_exists():
    return render_template('user_exists.html')

@app.route('/login/', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('index_admin' if username == 'admin' else 'user_page'))
        return render_template('invalid_credentials.html')
    response = make_response(render_template('login.html'))
    return response

@app.route('/logout/')
def logout():
    session.pop('username', None)
    response = make_response(redirect(url_for('home')))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/index_admin/')
@login_required
@no_cache
def index_admin():
    return render_template('index_admin.html')

@app.route('/admin_page/')
@login_required
@no_cache
def admin_page():
    return render_template('admin_page.html')

@app.route('/edit/', methods=['POST', 'GET'])
@login_required
@no_cache
def editar_usuario():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username != 'admin'")
    lista_usuarios = cursor.fetchall()
    conn.close()

    if request.method == 'POST':
        old_username = request.form['old_username']
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        hashed_password = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET username = ?, password = ? WHERE username = ?', (new_username, hashed_password, old_username))
        conn.commit()
        conn.close()
        return render_template('index_admin.html')
    return render_template('edit.html', lista_usuarios=lista_usuarios)

@app.route('/delete/', methods=['POST', 'GET'])
@login_required
@no_cache
def eliminar_usuario():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username != 'admin'")
    lista_usuarios = cursor.fetchall()
    conn.close()

    if request.method == 'POST':
        username = request.form['username']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        return redirect(url_for('index_admin'))
    return render_template('delete.html', lista_usuarios=lista_usuarios)

@app.route('/mostrar/', methods=['POST', 'GET'])
@login_required
@no_cache
def obtener_lista_usuarios():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, substr(password, 0, 30) FROM users")
    lista_usuarios = cursor.fetchall()
    conn.close()
    return render_template('mostrar.html', lista_usuarios=lista_usuarios)


"""@app.route('/tripulante/')
@login_required
@no_cache
def tripulante():
    return render_template('tripulante.html')

@app.route('/impostor/')
@login_required
@no_cache
def impostor():
    return render_template('impostor.html')"""

@app.route('/user_page/')
@login_required
@no_cache
def user_page():
    return render_template('user_page.html')

#RESTO DEL CODIGO

@app.route('/market/')
@login_required
@no_cache
def market():
    return render_template('market.html', peluches=peluches)

# Tabla de peluches a la venta
peluches = [
    {'id': 1, 'nombre': 'Oso Cariñoso', 'precio': 19.99, 'imagen': 'oso.jpg'},
    {'id': 2, 'nombre': 'Conejo Saltarín', 'precio': 14.99, 'imagen': 'conejo.jpg'},
    {'id': 3, 'nombre': 'Gato Tiburón', 'precio': 24.99, 'imagen': 'gato.jpg'},
    {'id': 4, 'nombre': 'Doom Slayer', 'precio': 24.99, 'imagen': 'doom-slayer.jpg'},
    {'id': 5, 'nombre': 'Sans (Undertale)', 'precio': 19.99, 'imagen': 'sans.jpg'},
    {'id': 6, 'nombre': 'Peppino (Pizza Tower)', 'precio': 19.99, 'imagen': 'peppino.jpg'},
    {'id': 7, 'nombre': 'Crewmate with Headphones (Among Us)', 'precio': 14.99, 'imagen': 'crewmate.jpg'},
    {'id': 8, 'nombre': 'Yoshi (Mario Bros)', 'precio': 14.99, 'imagen': 'yoshi.jpg'},
]

@app.route('/agregar/<int:peluche_id>')
@login_required
@no_cache
def agregar_al_carrito(peluche_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    username = session['username']

    try:
        # Obtener el ID del usuario
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user_id = cursor.fetchone()[0]

        # Verificar si el producto ya existe en el carrito
        cursor.execute('SELECT cantidad FROM carts WHERE user_id = ? AND peluche_id = ?', (user_id, peluche_id))
        resultado = cursor.fetchone()

        if resultado:
            # Si el producto ya está en el carrito, incrementa la cantidad
            nueva_cantidad = resultado[0] + 1
            cursor.execute('UPDATE carts SET cantidad = ? WHERE user_id = ? AND peluche_id = ?', (nueva_cantidad, user_id, peluche_id))
        else:
            # Si no está, añade el producto con cantidad inicial = 1
            cursor.execute('INSERT INTO carts (user_id, peluche_id, cantidad) VALUES (?, ?, 1)', (user_id, peluche_id))

        conn.commit()
        print("Producto agregado correctamente al carrito.")

    except sqlite3.Error as e:
        print(f"Error al agregar producto al carrito: {e}")

    finally:
        conn.close()

    return redirect(url_for('market'))

@app.route('/carrito')
@login_required
@no_cache
def carrito():
    username = session['username']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Obtener el ID del usuario
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user_id = cursor.fetchone()[0]

    # Obtener los productos del carrito junto con sus cantidades
    cursor.execute('''
        SELECT peluche_id, cantidad FROM carts WHERE user_id = ?
    ''', (user_id,))
    carrito_items = cursor.fetchall()

    items = []
    total = 0
    for peluche_id, cantidad in carrito_items:
        # Buscar el producto en la lista de peluches disponibles
        peluche = next((p for p in peluches if p['id'] == peluche_id), None)
        if peluche:
            peluche['cantidad'] = cantidad
            peluche['subtotal'] = peluche['precio'] * cantidad
            items.append(peluche)
            total += peluche['subtotal']

    conn.close()
    return render_template('cart.html', items=items, total=total)

@app.route('/localizacion')
@login_required
@no_cache
def localizacion():
    return render_template('location.html')

@app.route('/chatbot')
@login_required
@no_cache
def chatbot():
    return render_template('chatbot.html')

def open_browser():
    webbrowser.open('http://127.0.0.1:5000')

if __name__ == '__main__':
    threading.Timer(1, open_browser).start()
    app.run(debug=True)
