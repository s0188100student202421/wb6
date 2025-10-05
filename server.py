# server.py (PostgreSQL version, minimal changes from original)
from http.server import BaseHTTPRequestHandler, HTTPServer
import psycopg2
import psycopg2.extras
from psycopg2 import Error as PGE
import cgi
import re
import secrets
from http import cookies
import json
import base64
import jwt
import os
import hashlib
import datetime
import html
from html import escape


user_session = {} 

#----------Получение и настройка секретного ключа для JWT-------------------
SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("Warning: JWT_SECRET_KEY not set in environment. Using generated ephemeral key")
# --------------------------------------------------------------------------

# ------------- DB config (read/write hosts) -----------------
# По умолчанию использованы старые значения из твоего кода, но ты можешь переопределить через env:
# export DB_WRITE_HOST=192.168.56.10
# export DB_READ_HOST=192.168.56.11

def get_connection(read=True, allow_fallback=None, connect_timeout=5):
    if allow_fallback is None:
        allow_fallback = True if read else False
    if read:
        host_try = [DB_READ_HOST, DB_WRITE_HOST] if allow_fallback else [DB_READ_HOST]
    else:
        host_try = [DB_WRITE_HOST]
    last_exc = None

    for host in host_try:
        try:
            conn = psycopg2.connect(
                host=host,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                port=DB_PORT,
                connect_timeout=connect_timeout
            )
            if host == DB_READ_HOST and read:
                print(f"[DB] connected (read) to {host}")
            elif host == DB_WRITE_HOST and not read:
                print(f"[DB] connected (write) to {host}")
            else:
                print(f"[DB] connected fallback to {host} (read={read})")
            return conn
        except Exception as e:
            last_exc = e
            print(f"[DB] connection to {host} failed: {e}")
            continue
    raise last_exc

# ------------------------------------------------------------

#------------------Функции для JWT---------------------------------
def generate_jwt(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    # Если токен вернулся в виде байтов, декодируем в строку
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def verify_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# --------------------------------------------------------------------------

#---------------для кодирования/декодирования Base64------------------------
def safe_base64_encode(data):
    return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8')

def safe_base64_decode(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)  # Добавляем недостающие символы '='
    return base64.urlsafe_b64decode(data).decode("utf-8")
# --------------------------------------------------------------------------

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

#def fill_cookie ???

# +++++++++same++++++++++++

class HttpProcessor(BaseHTTPRequestHandler):
    # АУДИТ: Безопасная подача статических файлов
    def serve_static(self, rel_path):
        base_dir = os.path.abspath('wb6/static')  # АУДИТ: устанавливаем базовую директорию
        requested = os.path.normpath(os.path.join(base_dir, rel_path))  # АУДИТ: нормализуем путь
        if not requested.startswith(base_dir):  # АУДИТ: предотвращаем directory traversal
            self.send_error(403, "Forbidden")
            return
        try:
            with open(requested, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/css')
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, "File not found")

    def do_GET(self):
        if self.path.startswith("/wb6/static/"):
            try:
                mime_type = "text/css"
                with open(self.path[1:], 'rb') as file:
                    content = file.read()
                self.send_response(200)
                self.send_header('Content-Type', mime_type)
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_error(404, "File not found")
        elif self.path.startswith("/wb6/login"):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            try:
                file_path = os.path.join(os.path.dirname(__file__), "login.html")
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                self.wfile.write(content.encode('utf-8'))
            except FileNotFoundError:
                self.wfile.write(b"login.html not found")
        
        elif self.path == "/wb6/":
            cookie = cookies.SimpleCookie(self.headers.get("Cookie"))
            auth_token = cookie.get("auth_token")
            # Если JWT отсутствует — перенаправляем на страницу логина.
            if not auth_token or not verify_jwt(auth_token.value):
                self.send_response(302)
                self.send_header("Location", "/wb6/login")
                self.end_headers()
                return

            # Авторизованный пользователь: данные заполняем из таблицы (не из cookie)
            token_payload = verify_jwt(auth_token.value)
            user_id = token_payload.get("user_id")
            form_data = {}  # заполним данные заявки из БД
            try:
                # чтение — используем read=True (реплика, если настроена)
                connection = get_connection(read=True)
                cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                # Выбираем последнюю заявку данного пользователя
                cursor.execute("""
                    SELECT id, full_name, gender, phone, email, date, bio, agreement
                    FROM applications
                    WHERE user_id = %s
                    ORDER BY id DESC
                    LIMIT 1
                """, (user_id,))
                application = cursor.fetchone()
                if application:
                    form_data["fio"]    = application.get("full_name", "")
                    form_data["gender"] = application.get("gender", "")
                    form_data["phone"]  = application.get("phone", "")
                    form_data["email"]  = application.get("email", "")
                    # Для поля date, если тип DATE, приводим к строке:
                    form_data["date"]   = str(application.get("date", ""))
                    form_data["bio"]    = application.get("bio", "")
                    form_data["check"]  = "on" if application.get("agreement") else ""
                    app_id = application.get("id")
                else:
                    # Если записи нет, заполняем пустыми значениями
                    for field in ["fio", "gender", "phone", "email", "date", "bio", "check"]:
                        form_data[field] = ""
                    app_id = None

                # Выбираем языки по заявке, если есть запись
                if app_id:
                    cursor.execute("""
                        SELECT pl.guid
                        FROM programming_languages pl
                        JOIN application_languages al ON pl.id = al.language_id
                        WHERE al.application_id = %s
                    """, (app_id,))
                    langs = cursor.fetchall()
                    if langs:
                        form_data["languages"] = ",".join([row["guid"] for row in langs])
                    else:
                        form_data["languages"] = ""
                else:
                    form_data["languages"] = ""

                cursor.close()
                connection.close()
            except PGE as e:
                print(f"Database error: {e}")  # АУДИТ: логируем сервер-side
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
                return
            except Exception as e:
                print(f"Unexpected DB error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
                return

            # Загружаем HTML-шаблон страницы (server.html)
            try:
                with open("server.html", "r", encoding="utf-8") as file:
                    html_content = file.read()
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"server.html not found")
                return

            # Если в cookies установлен флаг успеха, вставляем блок с авто-сгенерированными данными
            success_cookie = cookie.get("success")
            if success_cookie and success_cookie.value == "1":
                # Используем данные автогенерации из cookies (например, для вывода сообщения)
                auto_login_val = cookie.get("login").value if cookie.get("login") else "Unknown"
                success_html = f'<div class="success-message">Data successfully sent! </div>'
                html_content = html_content.replace("<button type=\"submit\"", f"{success_html}<button type=\"submit\"")

            # Подставляем значения из form_data в шаблон
            for field, value in form_data.items():
                # Приводим значение к строке (если это не строка)
                if value is None:
                    replace_val = ""
                else:
                    replace_val = str(value)
                html_content = html_content.replace(f"{{{{{field}}}}}", replace_val)
            
            # Обработка радио-кнопок для gender
            gender_val = form_data.get("gender", "")
            if gender_val == "M":
                html_content = html_content.replace("{{#if gender == 'M'}}checked{{/if}}", "checked")
                html_content = html_content.replace("{{#if gender == 'F'}}checked{{/if}}", "")
            elif gender_val == "F":
                html_content = html_content.replace("{{#if gender == 'M'}}checked{{/if}}", "")
                html_content = html_content.replace("{{#if gender == 'F'}}checked{{/if}}", "checked")
            else:
                html_content = html_content.replace("{{#if gender == 'M'}}checked{{/if}}", "")
                html_content = html_content.replace("{{#if gender == 'F'}}checked{{/if}}", "")

            # Обработка селекторов для языков
            languages_val = form_data.get("languages", "")
            selected_languages = [lang.strip() for lang in languages_val.split(",") if lang.strip()]
            all_languages = [
                "Pascal", 
                "C", 
                "C++", 
                "JavaScript", 
                "PHP", 
                "Python",
                "Java", 
                "Haskell", 
                "Clojure", 
                "Scala"
            ]
            for lang in all_languages:
                pattern = f"{{{{#if languages contains '{lang}'}}}}selected{{{{/if}}}}"
                if lang in selected_languages:
                    html_content = html_content.replace(pattern, "selected")
                else:
                    html_content = html_content.replace(pattern, "")
            for field in ["fio", "gender", "phone", "email", "date", "bio", "languages", "check"]:
                html_content = html_content.replace(f"{{{{error_{field}}}}}", "")

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html_content.encode("utf-8"))
            return

        elif self.path == "/wb6/admin":
            cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
            auth_token = cookie.get("auth_token")
            if not auth_token or not verify_jwt(auth_token.value):
                self.send_response(302)
                self.send_header("Location", "/wb6/login")
                self.end_headers()
                return 
            payload = verify_jwt(auth_token.value)
            if payload.get('role') != 'admin':
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden: You are not an admin")
                return
            #именно здесь подтягивается html и отображается
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()

            try:
                connection = get_connection(read=True)
                cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                cursor.execute("SELECT * FROM programming_languages")
                languages = cursor.fetchall()

                cursor.execute("""
                    SELECT guid, COUNT(*) as count
                    FROM programming_languages
                    GROUP BY guid
                """)
                stats = cursor.fetchall()

                cursor.execute("""
                    SELECT * FROM applications;
                """)
                applications = cursor.fetchall()
                cursor.close()

                # Для каждой заявки подтянем языки (используем отдельное соединение/курсоры)
                connection2 = get_connection(read=True)
                cursor2 = connection2.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                for app in applications:
                    application_id = app['id']
                    cursor2.execute("""
                        SELECT pl.guid
                        FROM application_languages al
                        JOIN programming_languages pl ON al.language_id = pl.id
                        WHERE al.application_id = %s;
                    """, (application_id,))
                    selected_language = cursor2.fetchall()
                    selected_languages = ', '.join([lang['guid'] for lang in selected_language])
                    app['selected_languages'] = selected_languages

                cursor2.close()
                connection2.close()

                # Build HTML
                html_content = """
                <html>
                <head><title>Admin Panel</title></head>
                <body>
                    <h1>Applications</h1>
                    <table border="1">
                        <tr>
                            <th>ID</th>
                            <th>Full Name</th>
                            <th>Gender</th>
                            <th>Phone</th>
                            <th>Email</th>
                            <th>Date</th>
                            <th>Languages</th>
                            <th>Bio</th>
                            <th>Agreement</th>
                            <th>Actions</th>
                        </tr>
                """
                for app in applications:
                    html_content += f"""
                        <tr>
                            <td>{app['id']}</td>
                            <td>{app['full_name']}</td>
                            <td>{app['gender']}</td>
                            <td>{app['phone']}</td>
                            <td>{app['email']}</td>
                            <td>{app['date']}</td>
                            <td>{app['selected_languages']}</td>
                            <td>{app['bio']}</td>
                            <td>{app['agreement']}</td>
                            <td>
                                <a href="/wb6/admin/edit/{app['id']}">Edit</a>
                                <a href="/wb6/admin/delete/{app['id']}">Delete</a>
                            </td>
                        </tr>
                    """
                html_content += """
                    </table>
                    <h1>Statistics</h1>
                    <table border="1">
                        <tr>
                            <th>Language</th>
                            <th>Count</th>
                        </tr>
                """
                for stat in stats:
                    html_content += f"""
                    <tr>
                        <td> {stat['guid']} </td>
                        <td> {stat['count']}
                    </tr>
                """
                html_content += """
                    </table>
                </body>
                </html>
                """
                self.wfile.write(html_content.encode('utf-8'))
            except PGE as e:
                print(f"Database error: {e}")  # АУДИТ: логируем сервер-side
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception as e:
                print(f"Unexpected DB error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")

        elif self.path.startswith("/wb6/admin/edit/"):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            try:
                with open('form-edit.html', 'r', encoding='utf-8') as file:
                    html_content = file.read()
            except FileNotFoundError:
                self.wfile.write(b"server.html not found")
                return

            app_id = self.path.split('/')[-1]
            if app_id == "style.css": return 
            html_content = html_content.replace("{{app_id}}", app_id)
            form_data = {}
            try:
                connection = get_connection(read=True)
                cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute("""
                    SELECT full_name, gender, phone, email, date, bio, agreement
                    FROM applications
                    WHERE id = %s
                    ORDER BY id DESC
                    LIMIT 1
                """, (app_id,))
                application = cursor.fetchone()
                if application:
                    form_data["fio"]    = application.get("full_name", "")
                    form_data["gender"] = application.get("gender", "")
                    form_data["phone"]  = application.get("phone", "")
                    form_data["email"]  = application.get("email", "")
                    # Для поля date, если тип DATE, приводим к строке:
                    form_data["date"]   = str(application.get("date", ""))
                    form_data["bio"]    = application.get("bio", "")
                    form_data["check"]  = "on" if application.get("agreement") else ""
                    app_id = application.get("id")
                else:
                    # Если записи нет, заполняем пустыми значениями
                    for field in ["fio", "gender", "phone", "email", "date", "bio", "check"]:
                        form_data[field] = ""
                    app_id = None

                if app_id:
                    cursor.execute("""
                        SELECT pl.guid
                        FROM programming_languages pl
                        JOIN application_languages al ON pl.id = al.language_id
                        WHERE al.application_id = %s
                    """, (app_id,))
                    langs = cursor.fetchall()
                    if langs:
                        form_data["languages"] = ",".join([row["guid"] for row in langs])
                    else:
                        form_data["languages"] = ""
                else:
                    form_data["languages"] = ""

                for field, value in form_data.items():
                    # Приводим значение к строке (если это не строка)
                    if value is None:
                        replace_val = ""
                    else:
                        replace_val = str(value)
                    html_content = html_content.replace(f"{{{{{field}}}}}", replace_val)
                    
                # Обработка радио-кнопок для gender
                gender_val = form_data.get("gender", "")
                if gender_val == "M":
                    html_content = html_content.replace("{{#if gender == 'M'}}checked{{/if}}", "checked")
                    html_content = html_content.replace("{{#if gender == 'F'}}checked{{/if}}", "")
                elif gender_val == "F":
                    html_content = html_content.replace("{{#if gender == 'M'}}checked{{/if}}", "")
                    html_content = html_content.replace("{{#if gender == 'F'}}checked{{/if}}", "checked")
                else:
                    html_content = html_content.replace("{{#if gender == 'M'}}checked{{/if}}", "")
                    html_content = html_content.replace("{{#if gender == 'F'}}checked{{/if}}", "")

                # Обработка селекторов для языков
                languages_val = form_data.get("languages", "")
                selected_languages = [lang.strip() for lang in languages_val.split(",") if lang.strip()]
                all_languages = [
                    "Pascal", 
                    "C", 
                    "C++", 
                    "JavaScript", 
                    "PHP", 
                    "Python",
                    "Java", 
                    "Haskell", 
                    "Clojure", 
                    "Scala"
                ]
                for lang in all_languages:
                    pattern = f"{{{{#if languages contains '{lang}'}}}}selected{{{{/if}}}}"
                    if lang in selected_languages:
                        html_content = html_content.replace(pattern, "selected")
                    else:
                        html_content = html_content.replace(pattern, "")
                for field in ["fio", "gender", "phone", "email", "date", "bio", "languages", "check"]:
                    html_content = html_content.replace(f"{{{{error_{field}}}}}", "")

                for field, value in form_data.items():
                    if value:
                        html_content = html_content.replace(f"{{{{{field}}}}}", value)
                    else:
                        html_content = html_content.replace(f"{{{{{field}}}}}", "")

                for field in ['fio', 'phone', 'email', 'bio', 'languages', 'gender', 'check', 'date']:
                    html_content = html_content.replace(f"{{{{error_{field}}}}}", "")

                cursor.close()
                connection.close()
                self.wfile.write(html_content.encode('utf-8'))
            except PGE as e:
                print(f"Database error: {e}")  # АУДИТ: логируем сервер-side
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception as e:
                print(f"Unexpected DB error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")

        elif self.path.startswith("/wb6/admin/delete/"):
            cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
            auth_token = cookie.get("auth_token")
            if not auth_token or not verify_jwt(auth_token.value):
                self.send_response(302)
                self.send_header("Location", "/wb6/login")
                self.end_headers()
                return 
            payload = verify_jwt(auth_token.value)
            if payload.get('role') != 'admin':
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden: You are not an admin")
                return
            app_id = self.path.split('/')[-1]

            try:
                connection = get_connection(read=False)
                cursor = connection.cursor()
                cursor.execute("DELETE FROM applications WHERE id = %s", (app_id,))
                connection.commit()
                cursor.close()
                connection.close()

                self.send_response(302)
                self.send_header('Location', '/wb6/admin')
                self.end_headers()
            except PGE as e:
                print(f"Database error: {e}")  # АУДИТ: логируем сервер-side
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception as e:
                print(f"Unexpected DB error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith("/wb6/admin/edit/"):
            cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
            auth_token = cookie.get("auth_token")
            if not auth_token or not verify_jwt(auth_token.value):
                self.send_response(302)
                self.send_header("Location", "/wb6/login")
                self.end_headers()
                return 

            payload = verify_jwt(auth_token.value)
            if payload.get('role') != 'admin':
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden: You are not an admin")
                return
            app_id = self.path.split('/')[-1]

            form = cgi.FieldStorage(
                fp=self.rfile, 
                headers=self.headers, 
                environ={'REQUEST_METHOD': 'POST'}
            )

            fio = form.getvalue('fio')
            phone = form.getvalue('phone')
            email = form.getvalue('email')
            date = form.getvalue('date')
            gender = form.getvalue('gender')
            languages = form.getlist('languages')
            bio = form.getvalue('bio')
            check = form.getvalue('check')

            try:
                connection = get_connection(read=False)
                cursor = connection.cursor()
                cursor.execute("""
                    UPDATE applications 
                    SET full_name = %s, gender = %s, phone = %s, email = %s, date = %s, bio = %s, agreement = %s 
                    WHERE id = %s
                """, (fio, gender, phone, email, date, bio, bool(check), app_id))
                cursor.close()

                cursor = connection.cursor()
                cursor.execute("""
                    DELETE FROM application_languages WHERE application_id = %s
                """, (app_id,))
                cursor.close()  

                cursor = connection.cursor()
                for lang in languages:
                    cursor.execute("""
                        INSERT INTO programming_languages (guid)
                        VALUES (%s)
                        ON CONFLICT (guid) DO NOTHING
                    """, (lang,))

                    cursor.execute("SELECT id FROM programming_languages WHERE guid = %s", (lang,))
                    result = cursor.fetchone()
                    if result:
                        language_id = result[0]
                    else:
                        continue

                    cursor.execute("""
                        INSERT INTO application_languages (application_id, language_id)
                        VALUES (%s, %s)
                    """, (app_id, language_id))
                connection.commit()
                cursor.close()
                connection.close()

                self.send_response(302)
                self.send_header('Location', '/wb6/admin')
                self.end_headers()
            except PGE as e:
                print(f"Database error: {e}")  # АУДИТ: логируем сервер-side
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception as e:
                print(f"Unexpected DB error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
        
        elif self.path == "/wb6/login":
            form = cgi.FieldStorage(
                fp=self.rfile, 
                headers=self.headers, 
                environ={'REQUEST_METHOD': 'POST'}
            )
            login_input = form.getvalue("login")
            password_input = form.getvalue("password")
            role = "user"
            if not login_input or not password_input:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Login and password are required.")
                return
            elif login_input == "kovoya" and password_input == "admin123":
                role = "admin"
            try:
                connection = get_connection(read=True)
                cursor = connection.cursor()
                cursor.execute("SELECT user_id, hashed_password FROM users WHERE login = %s", (login_input,))
                result = cursor.fetchone()
                if result:
                    user_id, stored_hash = result
                    if stored_hash == hash_password(password_input):
                        token = generate_jwt(user_id, role)

                        # +++++++++same++++++++++++
                        cookie = cookies.SimpleCookie()
                        cookie["auth_token"] = token
                        cookie["auth_token"]["path"] = "/wb6/"
                        cookie["auth_token"]["max-age"] = 3600 
                        cookie["auth_token"]["httponly"] = True
                        # Сохраняем user_id в cookie
                        cookie["user_id"] = str(user_id)
                        cookie["user_id"]["path"] = "/wb6/"
                        cookie["user_id"]["max-age"] = 3600 
                        cookie["user_id"]["httponly"] = True
                        self.send_response(302)
                        self.send_header("Location", "/wb6/")
                        # +++++++++same++++++++++++
                        for morsel in cookie.values():
                            self.send_header("Set-Cookie", morsel.OutputString())
                        self.end_headers()
                        cursor.close()
                        connection.close()
                        return
                    else:
                        self.send_response(401)
                        self.end_headers()
                        self.wfile.write(b"Invalid login or password.")
                else:
                    try:
                        hashed_pwd = hash_password(password_input)
                        # Для вставки пользователя используем RETURNING user_id, поэтому подключаемся к мастеру (write)
                        connection2 = get_connection(read=False)
                        cursor2 = connection2.cursor()
                        cursor2.execute(
                            "INSERT INTO users (login, hashed_password) VALUES (%s,%s) RETURNING user_id",
                            (login_input, hashed_pwd)
                        )
                        user_row = cursor2.fetchone()
                        if user_row:
                            user_id = user_row[0]
                        else:
                            user_id = None
                        role = "user"
                        if login_input == "admin" and password_input == "admin":
                            role = "admin"
                        connection2.commit()
                        cursor2.close()
                        connection2.close()

                        token = generate_jwt(user_id,role)
                        # +++++++++same++++++++++++
                        cookie = cookies.SimpleCookie()
                        cookie["auth_token"] = token
                        cookie["auth_token"]["path"] = "/wb6/"
                        cookie["auth_token"]["max-age"] = 3600 
                        cookie["auth_token"]["httponly"] = True
                        # Сохраняем user_id в cookie
                        cookie["user_id"] = str(user_id)
                        cookie["user_id"]["path"] = "/wb6/"
                        cookie["user_id"]["max-age"] = 3600 
                        cookie["user_id"]["httponly"] = True
                        self.send_response(302)
                        self.send_header("Location", "/wb6/")
                        # +++++++++same++++++++++++
                        for morsel in cookie.values():
                            self.send_header("Set-Cookie", morsel.OutputString())
                        self.end_headers()
                    except PGE as e:
                        print(f"Database error: {e}")  # АУДИТ: логируем сервер-side
                        self.send_response(500)
                        self.end_headers()
                        self.wfile.write(b"Internal Server Error")
            except PGE as e:
                print(f"Database error: {e}")  # АУДИТ: логируем сервер-side
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception as e:
                print(f"Unexpected DB error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
        elif self.path == "/wb6/":
            cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
            auth_token = cookie.get("auth_token")
            user_id = cookie.get("user_id")
            if not auth_token or not verify_jwt(auth_token.value):
                self.send_response(302)
                self.send_header("Location", "/wb6/login")
                self.end_headers()
                return
            if not user_id:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"User ID not found in cookies.")
                return
            user_id = int(user_id.value)
            form = cgi.FieldStorage(
                fp=self.rfile, 
                headers=self.headers, 
                environ={'REQUEST_METHOD': 'POST'}
            )

            fio = form.getvalue('fio')
            phone = form.getvalue('phone')
            email = form.getvalue('email')
            date = form.getvalue('date')
            gender = form.getvalue('gender')
            languages = form.getlist('languages')
            bio = form.getvalue('bio')
            check = form.getvalue('check')

            errors = {}
            valid_fio = re.compile(r"^[A-Za-zА-Яа-яЁё ]+$")
            if not fio or not valid_fio.match(fio) or len(fio) > 150:
                errors["fio"] = "Недопустимые символы в поле 'ФИО'. Разрешены только буквы и пробелы."

            valid_phone = re.compile(r"^(?:\+7|8)[0-9]{10}$")
            if not phone or not valid_phone.match(phone):
                errors["phone"] = "Неверный номер телефона. Используйте формат +7XXXXXXXXXX."

            valid_email = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            if not email or not valid_email.match(email):
                errors["email"] = "Неверный email. Используйте формат example@domain.com."
            if not date:
                errors["date"] = "Пожалуйста укажите дату"
            if not gender:
                errors["gender"] = "Не выбран пол."

            if not languages:
                errors["languages"] = "Не выбран ни один язык программирования."

            if not bio or len(bio) > 500:
                errors["bio"] = "Неверная биография. Максимальная длина 500 символов."

            if not check:
                errors["check"] = "Необходимо согласие с контрактом."

            if errors:
                # +++++++++same++++++++++++
                cookie = cookies.SimpleCookie()
                for field in ['fio', 'phone', 'email', 'date', 'bio', 'gender', 'check','date']:
                    value = locals().get(field, '')
                    if value:
                        cookie[field] = safe_base64_encode(value)
                        cookie[field]['path'] = "/wb6/"
                        cookie[field]['httponly'] = True
                        cookie[field]['max-age'] = 31536000
                if languages:
                    cookie['languages'] = safe_base64_encode(",".join(languages))
                    cookie['languages']['path'] = "/wb6/"
                    cookie['languages']['httponly'] = True
                    cookie['languages']['max-age'] = 31536000

                cookie["errors"] = safe_base64_encode(json.dumps(errors, ensure_ascii=False))
                cookie["errors"]['path'] = "/wb6/"
                cookie["errors"]['httponly'] = True
                cookie["errors"]['max-age'] = 3600

                self.send_response(302)
                self.send_header('Location', "/wb6/")
                # +++++++++same++++++++++++
                for morsel in cookie.values():
                    self.send_header("Set-Cookie", morsel.OutputString())
                self.end_headers()
                return

            try:
                # вставка — используем мастер (read=False)
                connection = get_connection(read=False)
                cursor = connection.cursor()
                cursor.execute("""
                    INSERT INTO applications(user_id, full_name, gender, phone, email, date, bio, agreement)
                    VALUES (%s,%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (user_id, fio, gender, phone, email, date, bio, bool(check)))
                inserted = cursor.fetchone()
                if inserted:
                    application_id = inserted[0]
                else:
                    application_id = None

                for lang in languages:
                    cursor.execute("""
                        INSERT INTO programming_languages (guid)
                        VALUES (%s)
                        ON CONFLICT (guid) DO NOTHING
                    """, (lang,))
                    cursor.execute("SELECT id FROM programming_languages WHERE guid = %s", (lang,))
                    res = cursor.fetchone()
                    language_id = res[0] if res else None
                    if language_id:
                        cursor.execute("""
                            INSERT INTO application_languages (application_id, language_id)
                            VALUES(%s, %s)
                        """, (application_id, language_id))

                login = "Unknown"
                cursor.execute("SELECT login FROM users WHERE user_id = %s", (user_id,))
                login_result = cursor.fetchone()
                if login_result:
                    login = login_result[0]

                connection.commit()
                cursor.close()
                connection.close()
                # +++++++++same++++++++++++
                cookie = cookies.SimpleCookie()
                for field in ['fio', 'phone', 'email', 'date', 'bio', 'gender', 'check']:
                    value = locals().get(field, '')
                    cookie[field] = safe_base64_encode(value)
                    cookie[field]['path'] = "/wb6/"
                    cookie[field]['httponly'] = True
                    cookie[field]['max-age'] = 31536000
                if languages:
                    cookie['languages'] = safe_base64_encode(",".join(languages))
                    cookie['languages']['path'] = '/wb6/'
                    cookie['languages']['httponly'] = True
                    cookie['languages']['max-age'] = 31536000

                cookie['errors'] = ""
                cookie['errors']['path'] = '/wb6/'
                cookie['errors']['max-age'] = 31536000

                cookie['success'] = '1'
                cookie['languages']['path'] = '/wb6/'
                cookie['languages']['max-age'] = 100

                cookie['login'] = safe_base64_encode(login)
                cookie['languages']['path'] = '/wb6/'
                cookie['languages']['max-age'] = 100
                # +++++++++same++++++++++++
                self.send_response(302)
                self.send_header('Location', '/wb6/')
                for morsel in cookie.values():
                    self.send_header('Set-Cookie', morsel.OutputString())
                self.end_headers()

            except PGE as e:
                print(f"Database error: {e}")  # АУДИТ: логируем сервер-side
                try:
                    connection.rollback()
                except Exception:
                    pass
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception as e:
                print(f"Unexpected DB error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    port = 8080
    serv = HTTPServer(("0.0.0.0", port), HttpProcessor)
    print(f"Server is running on port {port}...")
    serv.serve_forever()
