from http.server import BaseHTTPRequestHandler, HTTPServer
import mysql.connector
from mysql.connector import Error
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

# В методе get мы отрисовываем новую форму просто+заполняем ее значениями из бд соотвественно, отображаем для пользователя+ кнопка submit и уже в пост методе 

#----------Получение и настройка секретного ключа для JWT-------------------
SECRET_KEY = os.environ.get('JWT_SECRET_KEY') 
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("Warning: JWT_SECRET_KEY not set in environment. Using generated ephemeral key")
# --------------------------------------------------------------------------

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
                connection = mysql.connector.connect(
                    host='u68824_3',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )

                cursor = connection.cursor(dictionary=True)
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
            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode("utf-8"))
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
                success_html = f'<div class="success-message">Data successfully sent! Login: {html.escape(auto_login_val)}</div>'
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
            #именно здесь подтягивается html и отображается
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()

            try:
                connection = mysql.connector.connect(
                    host='u68824_3',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )

                if connection.is_connected():
                    cursor = connection.cursor(dictionary=True)
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
                    cursor2 = connection.cursor(dictionary=True)
                    for app in applications:
                        application_id = app['id']
                        cursor2.execute("""
                            SELECT 
                                pl.guid
                            FROM
                                application_languages al
                            JOIN
                                programming_languages pl ON al.language_id = pl.id
                            WHERE
                                al.application_id = %s;
                        """, (application_id,))
                        selected_language = cursor2.fetchall()
                        selected_languages = ', '.join([lang['guid'] for lang in selected_language])
                        app['selected_languages'] = selected_languages

                    cursor2.close()
                    connection.close()
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
            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode('utf-8'))
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
            try:
                connection = mysql.connector.connect(
                    host='u68824_3',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )

                if connection.is_connected():
                    cursor = connection.cursor()
                    cursor.execute("""
                        SELECT * FROM applications WHERE id = %s
                    """,(app_id,))
                    application = cursor.fetchall()[0]
                    cursor.close()
                    form_data = {
                        'fio': application[1],
                        'phone': application[3],
                        'email': application[4],
                        'bio': application[6]
                    }
                    for field, value in form_data.items():
                        if value:
                            html_content = html_content.replace(f"{{{{{field}}}}}", value)
                        else:
                            html_content = html_content.replace(f"{{{{{field}}}}}", "")

                    for field in ['fio', 'phone', 'email', 'bio', 'languages', 'gender', 'check', 'date']:
                        html_content = html_content.replace(f"{{{{error_{field}}}}}", "")

                    self.wfile.write(html_content.encode('utf-8'))
            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode('utf-8'))
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
            app_id = self.path.split('/')[-1]

            try:
                connection = mysql.connector.connect(
                    host='u68824_3',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )

                if connection.is_connected():
                    cursor = connection.cursor()
                    cursor.execute("DELETE FROM applications WHERE id = %s", (app_id,))
                    connection.commit()
                    cursor.close()
                    connection.close()

                    self.send_response(302)
                    self.send_header('Location', '/admin')
                    self.end_headers()
            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode('utf-8'))
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
                connection = mysql.connector.connect(
                    host='u68824_3',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )

                if connection.is_connected():
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

                    cursor = connection.cursor(buffered=True)  # Используем буферизованный курсор
                    for lang in languages:

                        cursor.execute("""
                            INSERT IGNORE INTO programming_languages (guid)
                            VALUES (%s)
                        """, (lang,))

                        cursor.execute("SELECT id FROM programming_languages WHERE guid = %s", (lang,))
                        result = cursor.fetchone()  
                        if result:
                            language_id = result[0]
                        else:
                            self.wfile.write(f"Language {lang} not found after insert.")

                        cursor.execute("""
                            INSERT INTO application_languages (application_id, language_id)
                            VALUES (%s, %s)
                        """, (app_id, language_id))
                    connection.commit() 
                    cursor.close()

                    self.send_response(302)
                    self.send_header('Location', '/admin')
                    self.end_headers()
            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode('utf-8'))
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
                connection = mysql.connector.connect(
                    host='u68824_3',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )

                if connection.is_connected():
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
                            return
                        else:
                            self.send_response(401)
                            self.end_headers()
                            self.wfile.write(b"Invalid login or password.")
                    else:
                        try:
                            hashed_pwd = hash_password(password_input)
                            cursor.execute(
                                "INSERT INTO users (login, hashed_password) VALUES (%s,%s)",
                                (login_input, hashed_pwd)
                            )
                            role = "user"
                            if login_input == "admin" and password_input == "admin":
                                role = "admin"

                            user_id = cursor.lastrowid
                            connection.commit()
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
                        except Error as e:
                            self.send_response(500)
                            self.end_headers()
                            self.wfile.write(f"Database error: {e}".encode('utf-8'))
                    cursor.close()
                    connection.close()
            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode('utf-8'))
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
                    self.send_header('Set-Cookie', morsel.OutputString())
                self.end_headers()
                return

            try:
                connection = mysql.connector.connect(
                    host='u68824_3',
                    database='u68824',
                    user='u68824',
                    password='u68824'
                )
                if connection.is_connected():
                    cursor = connection.cursor(buffered=True)
                    cursor.execute("""
                        INSERT INTO applications(user_id, full_name, gender, phone, email, date, bio, agreement)
                        VALUES (%s,%s, %s, %s, %s, %s, %s, %s)
                    """, (user_id, fio, gender, phone, email, date, bio, bool(check)))
                    # в таблице programming languages id и названия связаны
                    #получаем application_id
                    application_id = cursor.lastrowid
                    for lang in languages:
                        cursor.execute("""
                            INSERT IGNORE INTO programming_languages (guid)
                            VALUES (%s)
                        """, (lang,))
                        cursor.execute("SELECT id FROM programming_languages WHERE guid = %s", (lang,))
                        language_id = cursor.fetchone()[0]
                    
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
                        cookie['languages']['path'] = '/wb5/'
                        cookie['languages']['httponly'] = True
                        cookie['languages']['max-age'] = 31536000

                    cookie['errors'] = ""
                    cookie['errors']['path'] = '/wb5/'
                    cookie['errors']['max-age'] = 31536000

                    cookie['success'] = '1'
                    cookie['languages']['path'] = '/wb5/'
                    cookie['languages']['max-age'] = 100

                    cookie['login'] = safe_base64_encode(login)
                    cookie['languages']['path'] = '/wb5/'
                    cookie['languages']['max-age'] = 100
                    # +++++++++same++++++++++++
                    self.send_response(302)
                    self.send_header('Location', '/wb6/')
                    for morsel in cookie.values():
                        self.send_header('Set-Cookie', morsel.OutputString())
                    self.end_headers()

            except Error as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Database error: {e}".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    port = 8010
    serv = HTTPServer(("0.0.0.0", port), HttpProcessor)
    print(f"Server is running on port {port}...")
    serv.serve_forever()
