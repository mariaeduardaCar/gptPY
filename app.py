from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from config import SECRET_KEY
from openai import OpenAI
import json
from datetime import datetime

# Carrega as variáveis do arquivo .env
load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = SECRET_KEY
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Configuração do OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post',
        'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
    },
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# Banco de dados SQLite
def init_db():
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuario (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            senha_hash TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historico_chat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            pergunta TEXT NOT NULL,
            resposta TEXT NOT NULL,
            data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuario (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Modelo de usuário
class Usuario(UserMixin):
    def __init__(self, id, nome, email):
        self.id = id
        self.nome = nome
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, nome, email FROM usuario WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"Carregando usuário: {user}")  # Para debug
    return Usuario(*user) if user else None

@app.route('/cadastro', methods=['POST'])
def cadastro():
    dados = request.get_json() or request.form
    nome = dados.get('nome')
    email = dados.get('email')
    senha_hash = dados.get('senha_hash')

    if not nome or not email or not senha_hash:
        return jsonify({"erro": "Todos os campos são obrigatórios"}), 400

    senha_hash = generate_password_hash(senha_hash)
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM usuario WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"erro": "E-mail já cadastrado"}), 400

    cursor.execute("INSERT INTO usuario (nome, email, senha_hash) VALUES (?, ?, ?)", (nome, email, senha_hash))
    conn.commit()
    conn.close()

    return jsonify({"mensagem": "Usuário cadastrado com sucesso!"}), 201

@app.route('/login', methods=['POST'])
def login():
    dados = request.json
    email = dados.get('email')
    senha_hash = dados.get('senha_hash')

    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, nome, senha_hash FROM usuario WHERE email = ?", (email,))
    usuario = cursor.fetchone()
    conn.close()

    if usuario and check_password_hash(usuario[2], senha_hash):
        login_user(Usuario(usuario[0], usuario[1], email))
        return jsonify({"mensagem": f"Bem-vindo, {usuario[1]}!", "redirect": "/"})

    return jsonify({"erro": "Credenciais inválidas"}), 401

@app.route('/login/google')
def login_google():
    return google.authorize_redirect(url_for('google_authorized', _external=True))

@app.route('/login/google/callback')
def google_authorized():
    token = google.authorize_access_token()
    if not token:
        return jsonify({"erro": "Falha no login com o Google."}), 400

    user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()

    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM usuario WHERE email = ?", (user_info['email'],))
    usuario = cursor.fetchone()

    if not usuario:
        cursor.execute("INSERT INTO usuario (nome, email) VALUES (?, ?)", (user_info['name'], user_info['email']))
        conn.commit()
        usuario_id = cursor.lastrowid
    else:
        usuario_id = usuario[0]

    conn.close()
    login_user(Usuario(usuario_id, user_info['name'], user_info['email']))
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"mensagem": "Logout realizado com sucesso!"})

@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('chat.html')
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    dados = request.get_json()
    pergunta = dados.get('pergunta')
    
    if not pergunta:
        return jsonify({"erro": "A pergunta é obrigatória"}), 400

    try:
        # Fazer a chamada para a API do OpenAI
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Você é um assistente especializado em Python e programação em geral. Forneça respostas claras e concisas."},
                {"role": "user", "content": pergunta}
            ]
        )
        
        resposta = completion.choices[0].message.content

        # Salvar no histórico
        conn = sqlite3.connect('chat.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO historico_chat (usuario_id, pergunta, resposta) VALUES (?, ?, ?)",
            (current_user.id, pergunta, resposta)
        )
        conn.commit()
        conn.close()

        return jsonify({
            "resposta": resposta,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({"erro": str(e)}), 500

@app.route('/historico')
@login_required
def historico():
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT pergunta, resposta, data_hora FROM historico_chat WHERE usuario_id = ? ORDER BY data_hora DESC",
        (current_user.id,)
    )
    historico = cursor.fetchall()
    conn.close()

    return jsonify([{
        "pergunta": h[0],
        "resposta": h[1],
        "data_hora": h[2]
    } for h in historico])

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
