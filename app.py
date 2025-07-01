import calendar
import subprocess

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import pyodbc
import hashlib
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from datetime import datetime, timedelta
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from io import BytesIO
from flask import send_file
import smtplib
import xlsxwriter
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
import pandas as pd
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session security


# MSSQL Database connection
def get_db_connection():
    CONNECTION_STRING = "DRIVER={SQL Server};SERVER=SRVMICRO;DATABASE=YAGCILAR;Trusted_Connection=yes;"
    conn = pyodbc.connect(CONNECTION_STRING)
    return conn


def get_db_connection2():
    CONNECTION_STRING2 = "Driver={SQL Server};Server=LOGO-ENT;Database=TIGERDB;UID=sa;PWD=YagciHol24*;Encrypt=False;TrustServerCertificate=True"
    conn = pyodbc.connect(CONNECTION_STRING2)
    return conn


def get_db_connection3():
    CONNECTION_STRING3 = "DRIVER={SQL Server};SERVER=SRVMICRO;DATABASE=MikroDB_V16_10;Trusted_Connection=yes;"
    conn = pyodbc.connect(CONNECTION_STRING3)
    return conn

def get_db_connection4():
    CONNECTION_STRING4 = "Driver={SQL Server};Server=192.168.4.84;Database=BarkoDB_V1_YDCPETROL;UID=sa;PWD=YagciHol24*;Encrypt=False;TrustServerCertificate=True"
    conn = pyodbc.connect(CONNECTION_STRING4)
    return conn
def get_db_connection5():
    CONNECTION_STRING5 = "DRIVER={SQL Server};SERVER=SRVMICRO;DATABASE=YDCLASTIK;Trusted_Connection=yes;"
    conn = pyodbc.connect(CONNECTION_STRING5)
    return conn
def get_db_connection6():
    CONNECTION_STRING6 = "Driver={SQL Server};Server=RIVER;Database=KantarDB;UID=sa;PWD=Rıv3542*;Encrypt=False;TrustServerCertificate=True"
    conn = pyodbc.connect(CONNECTION_STRING6)
    return conn

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Helper function to save user logs
def log_user_action(user_id, action_type, action_details=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    ip_address = request.remote_addr
    user_agent = request.user_agent.string

    cursor.execute("""
        INSERT INTO UserLogs (UserID, ActionType, ActionDetails, IPAddress, UserAgent)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, action_type, action_details, ip_address, user_agent))

    conn.commit()
    cursor.close()
    conn.close()


# Get user permissions for menus
def get_user_menu_permissions(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT m.MenuID, m.MenuName, m.MenuURL, m.ParentMenuID, m.MenuOrder, m.Icon, 
               rp.CanView, rp.CanAdd, rp.CanEdit, rp.CanDelete
        FROM Menus m
        INNER JOIN RolePermissions rp ON m.MenuID = rp.MenuID
        INNER JOIN UserRoles ur ON rp.RoleID = ur.RoleID
        WHERE ur.UserID = ? AND m.IsActive = 1 AND rp.CanView = 1
        ORDER BY m.ParentMenuID, m.MenuOrder
    """, (user_id))

    menu_permissions = {}
    menus = []
    while True:
        row = cursor.fetchone()
        if not row:
            break

        menu = {
            'id': row[0],
            'name': row[1],
            'url': row[2],
            'parent_id': row[3],
            'order': row[4],
            'icon': row[5],
            'can_view': row[6],
            'can_add': row[7],
            'can_edit': row[8],
            'can_delete': row[9]
        }
        menus.append(menu)

        # Store permission in dictionary for easy access
        menu_permissions[row[0]] = {
            'can_view': row[6],
            'can_add': row[7],
            'can_edit': row[8],
            'can_delete': row[9]
        }

    cursor.close()
    conn.close()

    # Build hierarchical menu structure
    menu_tree = []
    menu_dict = {menu['id']: menu for menu in menus}

    for menu in menus:
        if menu['parent_id'] is None:
            menu_tree.append(menu)
        else:
            parent = menu_dict.get(menu['parent_id'])
            if parent:
                if 'children' not in parent:
                    parent['children'] = []
                parent['children'].append(menu)

    return menu_tree, menu_permissions


# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfaya erişmek için giriş yapmalısınız.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfaya erişmek için giriş yapmalısınız.')
            return redirect(url_for('login'))

        if not session.get('is_admin', False):
            flash('Bu sayfaya erişim izniniz bulunmamaktadır.')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


def permission_required(menu_id, permission_type='view'):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Bu sayfaya erişmek için giriş yapmalısınız.')
                return redirect(url_for('login'))

            # Admin kullanıcısı ise direkt erişim izni ver
            if session.get('is_admin', False):
                return f(*args, **kwargs)

            # YDCBARKOD özel kullanıcısı için direkt erişim izni ver
            if session.get('username', '').upper() == 'YDCBARKOD':
                # Bu kısmı özellikle urun_barkodu sayfası için ekliyoruz
                if menu_id == 11 or request.path == '/urun-barkodu':
                    return f(*args, **kwargs)

            # Normal kullanıcılar için yetki kontrolü
            user_id = session['user_id']
            conn = get_db_connection()
            cursor = conn.cursor()

            permission_column = 'CanView'
            if permission_type == 'add':
                permission_column = 'CanAdd'
            elif permission_type == 'edit':
                permission_column = 'CanEdit'
            elif permission_type == 'delete':
                permission_column = 'CanDelete'

            cursor.execute(f"""
                SELECT COUNT(*)
                FROM RolePermissions rp
                INNER JOIN UserRoles ur ON rp.RoleID = ur.RoleID
                WHERE ur.UserID = ? AND rp.MenuID = ? AND rp.{permission_column} = 1
            """, (user_id, menu_id))

            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()

            if count == 0:
                flash('Bu işlem için yetkiniz bulunmamaktadır.')
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Kullanıcı adı ve şifre gereklidir.')
            return render_template('login.html')

        # Hash the password for comparison
        hashed_password = hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Kullanıcı bilgilerini sorgula - Logo ve LogoYetki alanlarını da al
        cursor.execute("""
            SELECT UserID, Username, Email, FullName, Logo, LogoYetki
            FROM Users 
            WHERE Username = ? AND Password = ? AND IsActive = 1
        """, (username, hashed_password))

        user = cursor.fetchone()

        if user:
            # Update last login date
            cursor.execute("""
                UPDATE Users 
                SET LastLoginDate = GETDATE() 
                WHERE UserID = ?
            """, (user[0]))
            conn.commit()

            # Kullanıcı adı "admin" ise admin yetkisi ver
            is_admin = (username.lower() == "admin")

            # Store user info in session including Logo and LogoYetki
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[2]
            session['fullname'] = user[3]
            session['is_admin'] = is_admin
            session['logo'] = user[4] if len(user) > 4 and user[4] is not None else 'HAVUZ'
            session['logoyetki'] = user[5] if len(user) > 5 and user[5] is not None else 0

            # Log the login action
            log_user_action(user[0], 'LOGIN', 'Kullanıcı başarıyla giriş yaptı')

            # Redirect based on user type
            if is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Kullanıcı adı veya şifre hatalı!')

        cursor.close()
        conn.close()

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    # Get user menu permissions - her seferinde veritabanından taze veri al
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Menü izinlerini her ziyarette session'a kaydet
    session['menu_permissions'] = menu_permissions

    # Admin kullanıcıları için admin paneline erişim linki gösterilsin
    is_admin = session.get('is_admin', False)

    return render_template('dashboard.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           is_admin=is_admin)


@app.route('/admin')
@login_required
def admin_redirect():
    # Admin rolüne sahip kullanıcılar için admin paneline yönlendirme
    if session.get('is_admin', False):
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Bu sayfaya erişim izniniz bulunmamaktadır.')
        return redirect(url_for('dashboard'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get user menu permissions
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    return render_template('admin/dashboard.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions)


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_user_action(session['user_id'], 'LOGOUT', 'Kullanıcı çıkış yaptı')

    # Clear session
    session.clear()
    flash('Başarıyla çıkış yaptınız!')
    return redirect(url_for('login'))


# 2. Şifre Sıfırlama E-postası (paste-2.txt'den)
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT UserID, Username FROM Users WHERE Email = ?", (email,))
        user = cursor.fetchone()

        if user:
            # Generate a reset token
            reset_token = str(uuid.uuid4())
            expiry_date = datetime.now() + timedelta(hours=24)  # Token valid for 24 hours

            # Save token in database
            cursor.execute("""
                INSERT INTO PasswordResets (UserID, ResetToken, ExpiryDate)
                VALUES (?, ?, ?)
            """, (user[0], reset_token, expiry_date))
            conn.commit()

            # Send email with reset link
            reset_link = request.host_url + url_for('reset_password', token=reset_token)

            # Gmail SMTP ayarları
            sender_email = "yagcilarholding1@gmail.com"
            sender_password = "bqnp sius nztz padc"

            # Create message
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = email
            message["Subject"] = "Şifre Sıfırlama Talebi"

            # Email content
            body = f"""
            Merhaba {user[1]},

            Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın:
            {reset_link}

            Bu bağlantı 24 saat boyunca geçerlidir.

            Eğer şifre sıfırlama talebinde bulunmadıysanız, bu e-postayı dikkate almayın.

            Saygılarımızla,
            Yağcılar Holding - Yazılım Departmanı
            """

            message.attach(MIMEText(body, "plain"))

            try:
                # Gmail SMTP bağlantısı
                server = smtplib.SMTP("smtp.gmail.com", 587)
                server.starttls()  # Gmail için TLS gerekli
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, email, message.as_string())
                server.quit()

                flash('Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.')

                # Log action
                log_user_action(user[0], 'PASSWORD_RESET_REQUEST', f'Şifre sıfırlama e-postası gönderildi: {email}')

            except Exception as e:
                flash('E-posta gönderilirken bir hata oluştu. Lütfen daha sonra tekrar deneyin.')
                print(f"Error sending email: {e}")
                # Consider logging this error more securely
        else:
            # Don't reveal that email doesn't exist for security
            flash('Şifre sıfırlama bağlantısı e-posta adresinize gönderildi (varsa).')

        cursor.close()
        conn.close()

        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Check if token is valid
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT pr.UserID, u.Username 
        FROM PasswordResets pr
        INNER JOIN Users u ON pr.UserID = u.UserID
        WHERE pr.ResetToken = ? AND pr.ExpiryDate > GETDATE() AND pr.IsUsed = 0
    """, (token,))

    reset_info = cursor.fetchone()

    if not reset_info:
        flash('Geçersiz veya süresi dolmuş şifre sıfırlama bağlantısı.')
        cursor.close()
        conn.close()
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Şifreler eşleşmiyor!')
            return render_template('reset_password.html', token=token, username=reset_info[1])

        # Update password
        hashed_password = hash_password(new_password)
        cursor.execute("""
            UPDATE Users SET Password = ?, ModifiedDate = GETDATE() WHERE UserID = ?
        """, (hashed_password, reset_info[0]))

        # Mark token as used
        cursor.execute("""
            UPDATE PasswordResets SET IsUsed = 1 WHERE ResetToken = ?
        """, (token,))

        conn.commit()

        # Log action
        log_user_action(reset_info[0], 'PASSWORD_RESET', 'Şifre başarıyla sıfırlandı')

        flash('Şifreniz başarıyla sıfırlandı. Yeni şifrenizle giriş yapabilirsiniz.')

        cursor.close()
        conn.close()
        return redirect(url_for('login'))

    cursor.close()
    conn.close()
    return render_template('reset_password.html', token=token, username=reset_info[1])


from datetime import datetime


# Admin User Management Routes
@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT u.UserID, u.Username, u.Email, u.FullName, u.IsActive, u.LastLoginDate,
               STRING_AGG(r.RoleName, ', ') AS Roles, u.Logo, u.LogoYetki
        FROM Users u
        LEFT JOIN UserRoles ur ON u.UserID = ur.UserID
        LEFT JOIN Roles r ON ur.RoleID = r.RoleID
        GROUP BY u.UserID, u.Username, u.Email, u.FullName, u.IsActive, u.LastLoginDate, u.Logo, u.LogoYetki
        ORDER BY u.Username
    """)

    users = []
    while True:
        row = cursor.fetchone()
        if not row:
            break

        users.append({
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'fullname': row[3],
            'active': row[4],
            'last_login': row[5],
            'roles': row[6] if row[6] else 'No roles assigned',
            'logo': row[7] if len(row) > 7 and row[7] is not None else 'HAVUZ',
            'logoyetki': row[8] if len(row) > 8 and row[8] is not None else 0
        })

    cursor.close()
    conn.close()

    return render_template('admin/users/list.html', users=users)


@app.route('/admin/users/add', methods=['GET', 'POST'])
@admin_required
def admin_users_add():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        fullname = request.form.get('fullname')
        password = request.form.get('password')
        roles = request.form.getlist('roles')  # List of selected role IDs

        # Get the new Logo and LogoYetki fields
        logo = request.form.get('logo', 'HAVUZ')  # Default to 'HAVUZ' if not provided
        logoyetki = request.form.get('logoyetki', 0)  # Default to 0 if not provided

        # Convert logoyetki to integer
        try:
            logoyetki = int(logoyetki)
        except (ValueError, TypeError):
            logoyetki = 0

        # Validate input
        if not username or not email or not password:
            flash('Kullanıcı adı, e-posta ve şifre alanları zorunludur.')
            return redirect(url_for('admin_users_add'))

        # Hash password
        hashed_password = hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Check if username or email already exists
            cursor.execute("SELECT COUNT(*) FROM Users WHERE Username = ? OR Email = ?", (username, email))
            if cursor.fetchone()[0] > 0:
                flash('Bu kullanıcı adı veya e-posta adresi zaten kullanılıyor.')
                cursor.close()
                conn.close()
                return redirect(url_for('admin_users_add'))

            # Insert new user with Logo and LogoYetki fields
            cursor.execute("""
                INSERT INTO Users (Username, Password, Email, FullName, IsActive, Logo, LogoYetki)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (username, hashed_password, email, fullname, logo, logoyetki))

            # Get the new user ID
            cursor.execute("SELECT @@IDENTITY")
            user_id = cursor.fetchone()[0]

            # Assign roles
            for role_id in roles:
                cursor.execute("""
                    INSERT INTO UserRoles (UserID, RoleID)
                    VALUES (?, ?)
                """, (user_id, role_id))

            conn.commit()

            # Log action
            log_user_action(session['user_id'], 'ADD_USER', f'Yeni kullanıcı eklendi: {username}')

            flash('Kullanıcı başarıyla eklendi.')
            return redirect(url_for('admin_users'))

        except Exception as e:
            conn.rollback()
            flash(f'Kullanıcı eklenirken bir hata oluştu: {str(e)}')
        finally:
            cursor.close()
            conn.close()

    # Get available roles for dropdown
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT RoleID, RoleName FROM Roles ORDER BY RoleName")

    roles = []
    while True:
        row = cursor.fetchone()
        if not row:
            break
        roles.append({'id': row[0], 'name': row[1]})

    cursor.close()
    conn.close()

    return render_template('admin/users/add.html', roles=roles)


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_users_edit(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        email = request.form.get('email')
        fullname = request.form.get('fullname')
        is_active = 1 if request.form.get('is_active') else 0
        roles = request.form.getlist('roles')  # List of selected role IDs

        # Get the Logo and LogoYetki fields
        logo = request.form.get('logo', 'HAVUZ')
        logoyetki = request.form.get('logoyetki', 0)

        # Convert logoyetki to integer
        try:
            logoyetki = int(logoyetki)
        except (ValueError, TypeError):
            logoyetki = 0

        try:
            # Update user info including Logo and LogoYetki fields
            cursor.execute("""
                UPDATE Users 
                SET Email = ?, FullName = ?, IsActive = ?, ModifiedDate = GETDATE(),
                    Logo = ?, LogoYetki = ?
                WHERE UserID = ?
            """, (email, fullname, is_active, logo, logoyetki, user_id))

            # Remove existing roles
            cursor.execute("DELETE FROM UserRoles WHERE UserID = ?", (user_id,))

            # Assign new roles
            for role_id in roles:
                cursor.execute("""
                    INSERT INTO UserRoles (UserID, RoleID)
                    VALUES (?, ?)
                """, (user_id, role_id))

            conn.commit()

            # Log action
            log_user_action(session['user_id'], 'EDIT_USER', f'Kullanıcı düzenlendi: ID={user_id}')

            flash('Kullanıcı bilgileri başarıyla güncellendi.')
            return redirect(url_for('admin_users'))

        except Exception as e:
            conn.rollback()
            flash(f'Kullanıcı güncellenirken bir hata oluştu: {str(e)}')

    # Get user data including Logo and LogoYetki fields
    cursor.execute("""
        SELECT UserID, Username, Email, FullName, IsActive, Logo, LogoYetki
        FROM Users
        WHERE UserID = ?
    """, (user_id,))

    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        flash('Kullanıcı bulunamadı.')
        return redirect(url_for('admin_users'))

    user_data = {
        'id': user[0],
        'username': user[1],
        'email': user[2],
        'fullname': user[3],
        'active': user[4],
        'logo': user[5] if len(user) > 5 and user[5] is not None else 'HAVUZ',
        'logoyetki': user[6] if len(user) > 6 and user[6] is not None else 0
    }

    # Get all available roles
    cursor.execute("SELECT RoleID, RoleName FROM Roles ORDER BY RoleName")

    roles = []
    while True:
        row = cursor.fetchone()
        if not row:
            break
        roles.append({'id': row[0], 'name': row[1]})

    # Get user's current roles
    cursor.execute("SELECT RoleID FROM UserRoles WHERE UserID = ?", (user_id,))

    user_roles = []
    while True:
        row = cursor.fetchone()
        if not row:
            break
        user_roles.append(row[0])

    cursor.close()
    conn.close()

    return render_template('admin/users/edit.html', user=user_data, roles=roles, user_roles=user_roles)


@app.route('/admin/roles')
@admin_required
def admin_roles():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT r.RoleID, r.RoleName, r.Description, COUNT(ur.UserID) AS UserCount
        FROM Roles r
        LEFT JOIN UserRoles ur ON r.RoleID = ur.RoleID
        GROUP BY r.RoleID, r.RoleName, r.Description
        ORDER BY r.RoleName
    """)

    roles = []
    while True:
        row = cursor.fetchone()
        if not row:
            break

        roles.append({
            'id': row[0],
            'name': row[1],
            'description': row[2],
            'user_count': row[3]
        })

    cursor.close()
    conn.close()

    return render_template('admin/roles/list.html', roles=roles)


@app.route('/admin/roles/permissions/<int:role_id>', methods=['GET', 'POST'])
@admin_required
def admin_role_permissions(role_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get role info
    cursor.execute("SELECT RoleID, RoleName FROM Roles WHERE RoleID = ?", (role_id,))
    role = cursor.fetchone()

    if not role:
        cursor.close()
        conn.close()
        flash('Rol bulunamadı.')
        return redirect(url_for('admin_roles'))

    if request.method == 'POST':
        # Get all menu IDs
        cursor.execute("SELECT MenuID FROM Menus")
        menu_ids = [row[0] for row in cursor.fetchall()]

        try:
            # Remove existing permissions
            cursor.execute("DELETE FROM RolePermissions WHERE RoleID = ?", (role_id,))

            # Add new permissions
            for menu_id in menu_ids:
                can_view = 1 if request.form.get(f'view_{menu_id}') else 0
                can_add = 1 if request.form.get(f'add_{menu_id}') else 0
                can_edit = 1 if request.form.get(f'edit_{menu_id}') else 0
                can_delete = 1 if request.form.get(f'delete_{menu_id}') else 0

                if can_view or can_add or can_edit or can_delete:
                    cursor.execute("""
                        INSERT INTO RolePermissions (RoleID, MenuID, CanView, CanAdd, CanEdit, CanDelete)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (role_id, menu_id, can_view, can_add, can_edit, can_delete))

            conn.commit()

            # Log action
            log_user_action(session['user_id'], 'UPDATE_ROLE_PERMISSIONS', f'Rol yetkileri güncellendi: {role[1]}')

            flash('Rol yetkileri başarıyla güncellendi.')
            return redirect(url_for('admin_roles'))

        except Exception as e:
            conn.rollback()
            flash(f'Rol yetkileri güncellenirken bir hata oluştu: {str(e)}')

    # Get all menus with their current permissions for this role
    cursor.execute("""
        SELECT m.MenuID, m.MenuName, m.MenuURL, m.ParentMenuID, 
               COALESCE(rp.CanView, 0) AS CanView,
               COALESCE(rp.CanAdd, 0) AS CanAdd,
               COALESCE(rp.CanEdit, 0) AS CanEdit,
               COALESCE(rp.CanDelete, 0) AS CanDelete
        FROM Menus m
        LEFT JOIN RolePermissions rp ON m.MenuID = rp.MenuID AND rp.RoleID = ?
        ORDER BY ISNULL(m.ParentMenuID, 0), m.MenuOrder
    """, (role_id,))

    menus = []
    while True:
        row = cursor.fetchone()
        if not row:
            break

        menus.append({
            'id': row[0],
            'name': row[1],
            'url': row[2],
            'parent_id': row[3],
            'can_view': row[4],
            'can_add': row[5],
            'can_edit': row[6],
            'can_delete': row[7]
        })

    # Get parent menu names for display
    menu_dict = {menu['id']: menu for menu in menus}
    for menu in menus:
        if menu['parent_id'] is not None:
            parent = menu_dict.get(menu['parent_id'])
            if parent:
                menu['parent_name'] = parent['name']
            else:
                menu['parent_name'] = 'Unknown'
        else:
            menu['parent_name'] = 'Main Menu'

    cursor.close()
    conn.close()

    return render_template('admin/roles/permissions.html', role={'id': role[0], 'name': role[1]}, menus=menus)


@app.route('/admin/menus')
@admin_required
def admin_menus():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT m.MenuID, m.MenuName, m.MenuURL, p.MenuName AS ParentMenuName, 
               m.MenuOrder, m.Icon, m.IsActive
        FROM Menus m
        LEFT JOIN Menus p ON m.ParentMenuID = p.MenuID
        ORDER BY ISNULL(m.ParentMenuID, 0), m.MenuOrder
    """)

    menus = []
    while True:
        row = cursor.fetchone()
        if not row:
            break

        menus.append({
            'id': row[0],
            'name': row[1],
            'url': row[2],
            'parent_name': row[3] if row[3] else 'Main Menu',
            'order': row[4],
            'icon': row[5],
            'active': row[6]
        })

    cursor.close()
    conn.close()

    return render_template('admin/menus/list.html', menus=menus)


@app.route('/admin/menus/add', methods=['GET', 'POST'])
@admin_required
def admin_menus_add():
    if request.method == 'POST':
        menu_name = request.form.get('menu_name')
        menu_url = request.form.get('menu_url')
        parent_id = request.form.get('parent_id') or None
        menu_order = request.form.get('menu_order') or 1
        icon = request.form.get('icon')
        is_active = 1 if request.form.get('is_active') else 0

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO Menus (MenuName, MenuURL, ParentMenuID, MenuOrder, Icon, IsActive)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (menu_name, menu_url, parent_id, menu_order, icon, is_active))

            conn.commit()

            # Log action
            log_user_action(session['user_id'], 'ADD_MENU', f'Yeni menü eklendi: {menu_name}')

            flash('Menü başarıyla eklendi.')
            return redirect(url_for('admin_menus'))

        except Exception as e:
            conn.rollback()
            flash(f'Menü eklenirken bir hata oluştu: {str(e)}')
        finally:
            cursor.close()
            conn.close()

    # Get parent menus for dropdown
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MenuID, MenuName FROM Menus WHERE ParentMenuID IS NULL ORDER BY MenuName")

    parent_menus = []
    while True:
        row = cursor.fetchone()
        if not row:
            break
        parent_menus.append({'id': row[0], 'name': row[1]})

    cursor.close()
    conn.close()

    return render_template('admin/menus/add.html', parent_menus=parent_menus)


@app.route('/admin/menus/edit/<int:menu_id>', methods=['GET', 'POST'])
@admin_required
def admin_menus_edit(menu_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        menu_name = request.form.get('menu_name')
        menu_url = request.form.get('menu_url')
        parent_id = request.form.get('parent_id') or None
        menu_order = request.form.get('menu_order') or 1
        icon = request.form.get('icon')
        is_active = 1 if request.form.get('is_active') else 0

        try:
            # Make sure we're not setting a menu as its own parent
            if parent_id and int(parent_id) == menu_id:
                flash('Bir menü kendisini üst menü olarak seçemez.')
                return redirect(url_for('admin_menus_edit', menu_id=menu_id))

            # Check if we're creating a circular reference
            if parent_id:
                # Check if this menu is a parent of the selected parent
                def is_parent_of(check_menu_id, potential_child_id):
                    cursor.execute("""
                        WITH MenuHierarchy AS (
                            SELECT MenuID, ParentMenuID
                            FROM Menus
                            WHERE MenuID = ?

                            UNION ALL

                            SELECT m.MenuID, m.ParentMenuID
                            FROM Menus m
                            INNER JOIN MenuHierarchy mh ON m.ParentMenuID = mh.MenuID
                        )
                        SELECT COUNT(*)
                        FROM MenuHierarchy
                        WHERE MenuID = ?
                    """, (potential_child_id, check_menu_id))

                    return cursor.fetchone()[0] > 0

                if is_parent_of(menu_id, int(parent_id)):
                    flash('Döngüsel menü yapısı oluşturulamaz.')
                    return redirect(url_for('admin_menus_edit', menu_id=menu_id))

            cursor.execute("""
                UPDATE Menus
                SET MenuName = ?, MenuURL = ?, ParentMenuID = ?, MenuOrder = ?, Icon = ?, IsActive = ?
                WHERE MenuID = ?
            """, (menu_name, menu_url, parent_id, menu_order, icon, is_active, menu_id))

            conn.commit()

            # Log action
            log_user_action(session['user_id'], 'EDIT_MENU', f'Menü düzenlendi: {menu_name}')

            flash('Menü başarıyla güncellendi.')
            return redirect(url_for('admin_menus'))

        except Exception as e:
            conn.rollback()
            flash(f'Menü güncellenirken bir hata oluştu: {str(e)}')

    # Get menu data
    cursor.execute("""
        SELECT MenuID, MenuName, MenuURL, ParentMenuID, MenuOrder, Icon, IsActive
        FROM Menus
        WHERE MenuID = ?
    """, (menu_id,))

    menu = cursor.fetchone()

    if not menu:
        cursor.close()
        conn.close()
        flash('Menü bulunamadı.')
        return redirect(url_for('admin_menus'))

    menu_data = {
        'id': menu[0],
        'name': menu[1],
        'url': menu[2],
        'parent_id': menu[3],
        'order': menu[4],
        'icon': menu[5],
        'active': menu[6]
    }

    # Get parent menus for dropdown (excluding current menu and its children)
    cursor.execute("""
        WITH MenuHierarchy AS (
            SELECT MenuID
            FROM Menus
            WHERE MenuID = ?

            UNION ALL

            SELECT m.MenuID
            FROM Menus m
            INNER JOIN MenuHierarchy mh ON m.ParentMenuID = mh.MenuID
        )
        SELECT m.MenuID, m.MenuName
        FROM Menus m
        WHERE m.ParentMenuID IS NULL
        AND m.MenuID NOT IN (SELECT MenuID FROM MenuHierarchy)
        ORDER BY m.MenuName
    """, (menu_id,))

    parent_menus = []
    while True:
        row = cursor.fetchone()
        if not row:
            break
        parent_menus.append({'id': row[0], 'name': row[1]})

    cursor.close()
    conn.close()

    return render_template('admin/menus/edit.html', menu=menu_data, parent_menus=parent_menus)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_password or not new_password or not confirm_password:
            flash('Tüm alanları doldurunuz.')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('Yeni şifreler eşleşmiyor.')
            return render_template('change_password.html')

        # Hash passwords
        hashed_current = hash_password(current_password)
        hashed_new = hash_password(new_password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify current password
        cursor.execute("""
            SELECT COUNT(*)
            FROM Users
            WHERE UserID = ? AND Password = ?
        """, (session['user_id'], hashed_current))

        if cursor.fetchone()[0] == 0:
            flash('Mevcut şifreniz hatalı.')
            cursor.close()
            conn.close()
            return render_template('change_password.html')

        # Update password
        cursor.execute("""
            UPDATE Users
            SET Password = ?, ModifiedDate = GETDATE()
            WHERE UserID = ?
        """, (hashed_new, session['user_id']))

        conn.commit()

        # Log action
        log_user_action(session['user_id'], 'CHANGE_PASSWORD', 'Kullanıcı şifresini değiştirdi')

        flash('Şifreniz başarıyla değiştirildi.')

        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')


# Route to check user permissions via AJAX
@app.route('/api/check-permission', methods=['POST'])
@login_required
def check_permission():
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400

    menu_id = request.json.get('menu_id')
    permission_type = request.json.get('permission_type', 'view')  # Default to view

    if not menu_id:
        return jsonify({'success': False, 'error': 'Menu ID is required'}), 400

    # Check permission in database
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    permission_column = 'CanView'
    if permission_type == 'add':
        permission_column = 'CanAdd'
    elif permission_type == 'edit':
        permission_column = 'CanEdit'
    elif permission_type == 'delete':
        permission_column = 'CanDelete'

    cursor.execute(f"""
        SELECT COUNT(*)
        FROM RolePermissions rp
        INNER JOIN UserRoles ur ON rp.RoleID = ur.RoleID
        WHERE ur.UserID = ? AND rp.MenuID = ? AND rp.{permission_column} = 1
    """, (user_id, menu_id))

    has_permission = cursor.fetchone()[0] > 0

    cursor.close()
    conn.close()

    return jsonify({'success': True, 'has_permission': has_permission})


# Route to check if user is admin via AJAX
@app.route('/api/check-admin', methods=['GET'])
@login_required
def check_admin():
    is_admin = session.get('is_admin', False)
    return jsonify({'success': True, 'is_admin': is_admin})


# Admin Role Management Routes
@app.route('/admin/roles/add', methods=['GET', 'POST'])
@admin_required
def admin_roles_add():
    if request.method == 'POST':
        role_name = request.form.get('role_name')
        description = request.form.get('description')

        if not role_name:
            flash('Rol adı zorunludur.')
            return render_template('admin/roles/add.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Check if role name already exists
            cursor.execute("SELECT COUNT(*) FROM Roles WHERE RoleName = ?", (role_name,))
            if cursor.fetchone()[0] > 0:
                flash('Bu rol adı zaten kullanılıyor.')
                cursor.close()
                conn.close()
                return render_template('admin/roles/add.html')

            # Insert new role
            cursor.execute("""
                INSERT INTO Roles (RoleName, Description)
                VALUES (?, ?)
            """, (role_name, description))

            conn.commit()

            # Log action
            log_user_action(session['user_id'], 'ADD_ROLE', f'Yeni rol eklendi: {role_name}')

            flash('Rol başarıyla eklendi.')
            return redirect(url_for('admin_roles'))

        except Exception as e:
            conn.rollback()
            flash(f'Rol eklenirken bir hata oluştu: {str(e)}')
        finally:
            cursor.close()
            conn.close()

    return render_template('admin/roles/add.html')


@app.route('/admin/roles/edit/<int:role_id>', methods=['GET', 'POST'])
@admin_required
def admin_roles_edit(role_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        role_name = request.form.get('role_name')
        description = request.form.get('description')

        if not role_name:
            flash('Rol adı zorunludur.')
            return redirect(url_for('admin_roles_edit', role_id=role_id))

        try:
            # Check if role name already exists for other roles
            cursor.execute("SELECT COUNT(*) FROM Roles WHERE RoleName = ? AND RoleID != ?", (role_name, role_id))
            if cursor.fetchone()[0] > 0:
                flash('Bu rol adı zaten kullanılıyor.')
                return redirect(url_for('admin_roles_edit', role_id=role_id))

            # Update role
            cursor.execute("""
                UPDATE Roles
                SET RoleName = ?, Description = ?
                WHERE RoleID = ?
            """, (role_name, description, role_id))

            conn.commit()

            # Log action
            log_user_action(session['user_id'], 'EDIT_ROLE', f'Rol düzenlendi: {role_name}')

            flash('Rol başarıyla güncellendi.')
            return redirect(url_for('admin_roles'))

        except Exception as e:
            conn.rollback()
            flash(f'Rol güncellenirken bir hata oluştu: {str(e)}')

    # Get role data
    cursor.execute("SELECT RoleID, RoleName, Description FROM Roles WHERE RoleID = ?", (role_id,))
    role = cursor.fetchone()

    if not role:
        cursor.close()
        conn.close()
        flash('Rol bulunamadı.')
        return redirect(url_for('admin_roles'))

    role_data = {
        'id': role[0],
        'name': role[1],
        'description': role[2]
    }

    cursor.close()
    conn.close()

    return render_template('admin/roles/edit.html', role=role_data)


@app.route('/admin/roles/delete/<int:role_id>', methods=['POST'])
@admin_required
def admin_roles_delete(role_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get role name for logging
        cursor.execute("SELECT RoleName FROM Roles WHERE RoleID = ?", (role_id,))
        role_name = cursor.fetchone()[0]

        # Check if role is being used by any users
        cursor.execute("SELECT COUNT(*) FROM UserRoles WHERE RoleID = ?", (role_id,))
        if cursor.fetchone()[0] > 0:
            flash('Bu rol kullanıcılara atanmış durumda, önce kullanıcılardan kaldırılmalıdır.')
            cursor.close()
            conn.close()
            return redirect(url_for('admin_roles'))

        # Delete role permissions first
        cursor.execute("DELETE FROM RolePermissions WHERE RoleID = ?", (role_id,))

        # Delete role
        cursor.execute("DELETE FROM Roles WHERE RoleID = ?", (role_id,))

        conn.commit()

        # Log action
        log_user_action(session['user_id'], 'DELETE_ROLE', f'Rol silindi: {role_name}')

        flash('Rol başarıyla silindi.')

    except Exception as e:
        conn.rollback()
        flash(f'Rol silinirken bir hata oluştu: {str(e)}')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_roles'))


@app.route('/urun-barkodu')
@login_required
@permission_required(menu_id=11, permission_type='view')  # Adjust menu_id based on your menu structure
def urun_barkodu():
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get product data from database (Mikroskop Verileri) - Cari adı ile birlikte
    conn = get_db_connection2()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT 
                MS.grpd_grup_no, 
                MS.grpd_CARIFIRMA,
                MS.grpd_PARCAADI,
                MS.grpd_PARCAMIKTAR,
                MS.grpd_PARCAKODU,
                ISNULL(CL.DEFINITION_, 'BILINMEYEN') as cari_adi
            FROM MS_ISEMRI_GRUPLAMA_D MS
            LEFT OUTER JOIN LG_225_CLCARD CL ON MS.grpd_CARIFIRMA = CL.CODE
            WHERE MS.grpd_grup_no LIKE 'YDC%'
            ORDER BY MS.grpd_KayNo desc
        """)

        urun_data = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Cari adının ilk 3 harfini al ve büyük harfe çevir
            cari_adi = row[5] if row[5] else 'BIL'
            cari_adi_kisaltma = cari_adi[:4].upper()

            urun_data.append({
                'grup_no': row[0],
                'cari_kod': row[1],
                'parca_adi': row[2],
                'parca_miktar': row[3],
                'parca_kodu': row[4],
                'cari_adi': cari_adi,
                'cari_adi_kisaltma': cari_adi_kisaltma
            })

    except Exception as e:
        flash(f'Veri çekilirken bir hata oluştu: {str(e)}', 'error')
        urun_data = []
    finally:
        cursor.close()
        conn.close()

    # Get Octopus data from YAGCILAR database
    conn = get_db_connection()  # YAGCILAR veritabanı için doğru bağlantı
    cursor = conn.cursor()

    try:
        # LazerParcalar ve LazerSiparisler verilerini al - CariAdi de dahil
        cursor.execute("""
            SELECT 
                lp.SiparisID,
                ls.CariKodu,
                ISNULL(ls.CariAdi, 'BILINMEYEN') as cari_adi,
                lp.PartNo,
                lp.ParcaKodu,
                lp.TotalQuantityInJob
            FROM LazerParcalar lp
            INNER JOIN LazerSiparisler ls ON lp.SiparisID = ls.SiparisID
            ORDER BY lp.SiparisID desc
        """)

        octopus_data = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Cari adının ilk 3 harfini al ve büyük harfe çevir
            cari_adi = row[2] if row[2] else 'BILINMEYEN'
            cari_adi_kisaltma = cari_adi[:4].upper()

            octopus_data.append({
                'grup_no': row[0],  # SiparisID
                'cari_kod': row[1],  # CariKodu
                'cari_adi': cari_adi,  # CariAdi (düzeltildi)
                'parca_adi': row[3],  # PartNo (düzeltildi)
                'parca_kodu': row[4],  # ParcaKodu
                'parca_miktar': row[5],  # TotalQuantityInJob
                'cari_adi_kisaltma': cari_adi_kisaltma
            })

    except Exception as e:
        flash(f'Oktapus verisi çekilirken bir hata oluştu: {str(e)}', 'error')
        octopus_data = []
    finally:
        cursor.close()
        conn.close()

    # Get personnel data
    conn = get_db_connection()  # Personel ve makine verileri için yeni bağlantı
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT TOP 1000
                personel_kodu,
                personel_adi,
                personel_gorev
            FROM Personeller
            ORDER BY personel_adi
        """)

        personeller = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            personeller.append({
                'personel_kodu': row[0],
                'personel_adi': row[1],
                'personel_gorev': row[2]
            })

    except Exception as e:
        flash(f'Personel verisi çekilirken bir hata oluştu: {str(e)}', 'error')
        personeller = []

    # Get machine data
    try:
        cursor.execute("""
            SELECT TOP 1000
                makine_kodu,
                makine_adi
            FROM Makineler
            ORDER BY makine_adi
        """)

        makineler = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            makineler.append({
                'makine_kodu': row[0],
                'makine_adi': row[1]
            })

    except Exception as e:
        flash(f'Makine verisi çekilirken bir hata oluştu: {str(e)}', 'error')
        makineler = []
    finally:
        cursor.close()
        conn.close()

    return render_template('urun_barkodu.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           urun_data=urun_data,
                           octopus_data=octopus_data,  # Added octopus data
                           personeller=personeller,
                           makineler=makineler)


@app.route('/urun-barkodu/print', methods=['POST'])
@login_required
def urun_barkodu_print():
    # Get selected items for printing
    selected_items = request.json.get('selectedItems', [])

    if not selected_items:
        return jsonify({'success': False, 'error': 'Hiç ürün seçilmedi'})

    # In a real application, we might want to generate and save PDFs,
    # or pass this data to a template that's designed for printing

    return jsonify({
        'success': True,
        'message': f'{len(selected_items)} ürün için barkodlar hazırlandı',
        'items': selected_items
    })


@app.route('/gunluk-yapilanlar')
@login_required
@permission_required(menu_id=8, permission_type='view')
def gunluk_yapilanlar():
    """Günlük yapılanlar sayfası."""
    username = session['username']
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    # Günlük yapılanlar verilerini getir - sadece kullanıcının kendi kayıtlarını göster
    conn = get_db_connection3()
    cursor = conn.cursor()

    try:
        # Admin kullanıcılarına tüm kayıtları, normal kullanıcılara sadece kendi kayıtlarını göster
        is_admin = session.get('is_admin', False)

        if is_admin:
            cursor.execute("""
                SELECT TOP 100
                    CONVERT(VARCHAR(36), Gun_ID) AS Gun_ID_Str,
                    Gun_Olusturan,
                    Gun_Tarih,
                    Gun_Cari_Proje,
                    Gun_Konu,
                    Gun_Detay,
                    Gun_Miktar,
                    Gun_Adet
                FROM YH_GUNLUK_YAPILANLAR
                ORDER BY Gun_Tarih DESC
            """)
        else:
            cursor.execute("""
                SELECT TOP 100
                    CONVERT(VARCHAR(36), Gun_ID) AS Gun_ID_Str,
                    Gun_Olusturan,
                    Gun_Tarih,
                    Gun_Cari_Proje,
                    Gun_Konu,
                    Gun_Detay,
                    Gun_Miktar,
                    Gun_Adet
                FROM YH_GUNLUK_YAPILANLAR
                WHERE Gun_Olusturan = ?
                ORDER BY Gun_Tarih DESC
            """, (username,))

        gunluk_data = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            gunluk_data.append({
                'id': row[0],
                'olusturan_username': row[1],
                'tarih': row[2],
                'cari_proje': row[3],
                'konu': row[4],
                'detay': row[5],
                'miktar': row[6],
                'adet': row[7]
            })

    except Exception as e:
        flash(f'Günlük yapılanlar verileri alınırken bir hata oluştu: {str(e)}', 'error')
        gunluk_data = []
    finally:
        cursor.close()
        conn.close()

    return render_template('gunluk_yapilanlar.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           gunluk_data=gunluk_data,
                           is_admin=session.get('is_admin', False),
                           now=now)


@app.route('/gunluk-yapilanlar/add', methods=['POST'])
@login_required
@permission_required(menu_id=8, permission_type='add')
def gunluk_yapilanlar_add():
    """Günlük yapılanlar ekleme."""
    if request.method == 'POST':
        try:
            # Form verilerini al
            cari_proje = request.form.get('cari_proje')
            konu = request.form.get('konu')
            detay = request.form.get('detay')
            miktar = request.form.get('miktar') or 0
            adet = request.form.get('adet') or 0
            tarih = request.form.get('tarih') or datetime.now().strftime('%Y-%m-%d')

            # Username'i al (User ID yerine)
            username = session['username']
            user_id = session['user_id']  # Log için hala gerekli

            # Sayısal değerleri kontrol et
            try:
                miktar = float(miktar)
                adet = int(adet)
            except ValueError:
                miktar = 0
                adet = 0

            # Veritabanına ekle
            conn = get_db_connection3()
            cursor = conn.cursor()

            try:
                # NEWID() kullanarak yeni bir uniqueidentifier oluştur
                # Gun_Firma alanı için 0 değerini otomatik ekle
                # Gun_Olusturan alanına username kaydediliyor
                cursor.execute("""
                    INSERT INTO YH_GUNLUK_YAPILANLAR 
                    (Gun_ID, Gun_Olusturan, Gun_Tarih, Gun_Cari_Proje, Gun_Konu, Gun_Detay, Gun_Miktar, Gun_Adet, Gun_Firma)
                    VALUES (NEWID(), ?, ?, ?, ?, ?, ?, ?, 0)
                """, (
                    username,  # Username kaydediliyor
                    tarih,
                    cari_proje,
                    konu,
                    detay,
                    miktar,
                    adet
                ))

                conn.commit()

                # İşlemi logla (Log için user_id kullanılıyor)
                log_user_action(user_id, 'GUNLUK_EKLE', f'Günlük yapılan eklendi: {konu}')

                flash('Kayıt başarıyla eklendi.', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Kayıt eklenirken bir hata oluştu: {str(e)}', 'error')
            finally:
                cursor.close()
                conn.close()

        except Exception as e:
            flash(f'İşlem sırasında bir hata oluştu: {str(e)}', 'error')

    return redirect(url_for('gunluk_yapilanlar'))


@app.route('/gunluk-yapilanlar/edit/<string:gunluk_id>', methods=['GET', 'POST'])
@login_required
def gunluk_yapilanlar_edit(gunluk_id):
    """Günlük yapılanlar düzenleme - HER KULLANICI DÜZENLEYEBİLİR."""
    username = session['username']
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)
    is_admin = session.get('is_admin', False)

    # Kaydı veritabanından al
    conn = get_db_connection3()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT 
                CONVERT(VARCHAR(36), Gun_ID) AS Gun_ID_Str,
                Gun_Olusturan,
                Gun_Tarih,
                Gun_Cari_Proje,
                Gun_Konu,
                Gun_Detay,
                Gun_Miktar,
                Gun_Adet
            FROM YH_GUNLUK_YAPILANLAR
            WHERE Gun_ID = ?
        """, (gunluk_id,))

        row = cursor.fetchone()

        if not row:
            flash('Kayıt bulunamadı.', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('gunluk_yapilanlar'))

        # YETKİ KONTROLÜ KALDIRILDI - HER KULLANICI DÜZENLEYEBİLİR
        # can_edit = True  # Artık herkes düzenleyebilir

        # POST işlemi için güncelleme
        if request.method == 'POST':
            # Form verilerini al
            cari_proje = request.form.get('cari_proje')
            konu = request.form.get('konu')
            detay = request.form.get('detay')
            miktar = request.form.get('miktar') or 0
            adet = request.form.get('adet') or 0

            # Sayısal değerleri kontrol et
            try:
                miktar = float(miktar)
                adet = int(adet)
            except ValueError:
                miktar = 0
                adet = 0

            # Veritabanına güncelle
            try:
                cursor.execute("""
                    UPDATE YH_GUNLUK_YAPILANLAR 
                    SET Gun_Cari_Proje = ?, Gun_Konu = ?, Gun_Detay = ?, Gun_Miktar = ?, Gun_Adet = ?
                    WHERE Gun_ID = ?
                """, (
                    cari_proje,
                    konu,
                    detay,
                    miktar,
                    adet,
                    gunluk_id
                ))

                conn.commit()

                # İşlemi logla
                log_user_action(user_id, 'GUNLUK_GUNCELLE', f'Günlük yapılan güncellendi: ID={gunluk_id}')

                flash('Kayıt başarıyla güncellendi.', 'success')
                cursor.close()
                conn.close()
                return redirect(url_for('gunluk_yapilanlar'))
            except Exception as e:
                conn.rollback()
                flash(f'Kayıt güncellenirken bir hata oluştu: {str(e)}', 'error')

        # GET işlemi için form verileri
        gunluk_item = {
            'id': row[0],
            'olusturan_username': row[1],
            'tarih': row[2].strftime('%Y-%m-%d') if row[2] else None,
            'cari_proje': row[3],
            'konu': row[4],
            'detay': row[5],
            'miktar': row[6],
            'adet': row[7],
        }

    except Exception as e:
        flash(f'Veriler alınırken bir hata oluştu: {str(e)}', 'error')
        return redirect(url_for('gunluk_yapilanlar'))
    finally:
        if 'row' not in locals():
            cursor.close()
            conn.close()
            return redirect(url_for('gunluk_yapilanlar'))

    # Edit formunu göster
    cursor.close()
    conn.close()

    return render_template('gunluk_yapilanlar_edit.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           gunluk_item=gunluk_item,
                           is_admin=is_admin)


@app.route('/gunluk-yapilanlar/delete/<string:gunluk_id>', methods=['POST'])
@login_required
def gunluk_yapilanlar_delete(gunluk_id):
    """Günlük yapılanlar silme - HER KULLANICI SİLEBİLİR."""
    username = session['username']
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)

    # Kaydı veritabanından kontrol et
    conn = get_db_connection3()
    cursor = conn.cursor()

    try:
        # Kaydın var olduğunu kontrol et
        cursor.execute("""
            SELECT CONVERT(VARCHAR(36), Gun_ID) AS Gun_ID_Str, Gun_Olusturan, Gun_Konu 
            FROM YH_GUNLUK_YAPILANLAR
            WHERE Gun_ID = ?
        """, (gunluk_id,))

        row = cursor.fetchone()

        if not row:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Kayıt bulunamadı.'})

        # YETKİ KONTROLÜ KALDIRILDI - HER KULLANICI SİLEBİLİR
        # can_delete = True  # Artık herkes silebilir

        # Kaydı sil
        cursor.execute("DELETE FROM YH_GUNLUK_YAPILANLAR WHERE Gun_ID = ?", (gunluk_id,))

        conn.commit()

        # İşlemi logla
        log_user_action(user_id, 'GUNLUK_SIL', f'Günlük yapılan silindi: {row[2]}')

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Kayıt başarıyla silindi.'})

    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': f'Kayıt silinirken bir hata oluştu: {str(e)}'})


@app.route('/gunluk-yapilanlar/download-excel')
@login_required
@permission_required(menu_id=8, permission_type='view')
def gunluk_yapilanlar_download_excel():
    """Günlük yapılanları Excel olarak indir."""
    import io
    import pandas as pd
    from flask import make_response

    user_id = session['user_id']
    username = session['username']  # Username'i al
    is_admin = session.get('is_admin', False)

    # Veritabanından verileri çek
    conn = get_db_connection3()
    cursor = conn.cursor()

    try:
        # Admin kullanıcılarına tüm kayıtları, normal kullanıcılara sadece kendi kayıtlarını göster
        if is_admin:
            cursor.execute("""
                SELECT 
                    Gun_Tarih,
                    Gun_Cari_Proje,
                    Gun_Konu,
                    Gun_Detay,
                    Gun_Miktar,
                    Gun_Adet,
                    Gun_Olusturan
                FROM YH_GUNLUK_YAPILANLAR
                ORDER BY Gun_Tarih DESC
            """)
        else:
            cursor.execute("""
                SELECT 
                    Gun_Tarih,
                    Gun_Cari_Proje,
                    Gun_Konu,
                    Gun_Detay,
                    Gun_Miktar,
                    Gun_Adet,
                    Gun_Olusturan
                FROM YH_GUNLUK_YAPILANLAR
                WHERE Gun_Olusturan = ?
                ORDER BY Gun_Tarih DESC
            """, (username,))  # user_id yerine username kullan

        # Verileri DataFrame'e dönüştür
        if is_admin:
            columns = ['Tarih', 'Cari/Proje', 'Konu', 'Detay', 'Miktar (KG)', 'Adet', 'Oluşturan']
        else:
            columns = ['Tarih', 'Cari/Proje', 'Konu', 'Detay', 'Miktar (KG)', 'Adet']

        rows = cursor.fetchall()

        data = []
        for row in rows:
            if is_admin:
                data.append({
                    'Tarih': row[0].strftime('%d.%m.%Y') if row[0] else '',
                    'Cari/Proje': row[1] or '',
                    'Konu': row[2] or '',
                    'Detay': row[3] or '',
                    'Miktar (KG)': float(row[4]) if row[4] else 0,
                    'Adet': int(row[5]) if row[5] else 0,
                    'Oluşturan': row[6] or ''
                })
            else:
                data.append({
                    'Tarih': row[0].strftime('%d.%m.%Y') if row[0] else '',
                    'Cari/Proje': row[1] or '',
                    'Konu': row[2] or '',
                    'Detay': row[3] or '',
                    'Miktar (KG)': float(row[4]) if row[4] else 0,
                    'Adet': int(row[5]) if row[5] else 0
                })

        df = pd.DataFrame(data, columns=columns)

        # Excel dosyası oluştur
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Günlük Yapılanlar', index=False)

            # Formatları ayarla
            workbook = writer.book
            worksheet = writer.sheets['Günlük Yapılanlar']

            # Kolon genişliklerini ayarla
            worksheet.set_column('A:A', 12)  # Tarih
            worksheet.set_column('B:B', 25)  # Cari/Proje
            worksheet.set_column('C:C', 20)  # Konu
            worksheet.set_column('D:D', 40)  # Detay
            worksheet.set_column('E:E', 12)  # Miktar
            worksheet.set_column('F:F', 10)  # Adet
            if is_admin:
                worksheet.set_column('G:G', 15)  # Oluşturan

        output.seek(0)

        # Response oluştur
        response = make_response(output.read())
        response.headers[
            'Content-Disposition'] = f'attachment; filename=gunluk_yapilanlar_{datetime.now().strftime("%d_%m_%Y")}.xlsx'
        response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        # İşlemi logla
        log_user_action(user_id, 'GUNLUK_DOWNLOAD_EXCEL', f'Günlük yapılanlar Excel olarak indirildi')

        return response

    except Exception as e:
        print(f"Excel indirme hatası: {e}")
        flash(f'Excel dosyası oluşturulurken bir hata oluştu: {str(e)}', 'error')
        return redirect(url_for('gunluk_yapilanlar'))
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/menus/delete/<int:menu_id>', methods=['POST'])
@admin_required
def admin_menus_delete(menu_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get menu name for logging
        cursor.execute("SELECT MenuName FROM Menus WHERE MenuID = ?", (menu_id,))
        menu_name = cursor.fetchone()[0]

        # Check if menu has children
        cursor.execute("SELECT COUNT(*) FROM Menus WHERE ParentMenuID = ?", (menu_id,))
        if cursor.fetchone()[0] > 0:
            flash('Bu menünün alt menüleri bulunmaktadır, önce alt menüler silinmelidir.')
            cursor.close()
            conn.close()
            return redirect(url_for('admin_menus'))

        # Delete menu permissions first
        cursor.execute("DELETE FROM RolePermissions WHERE MenuID = ?", (menu_id,))

        # Delete menu
        cursor.execute("DELETE FROM Menus WHERE MenuID = ?", (menu_id,))

        conn.commit()

        # Log action
        log_user_action(session['user_id'], 'DELETE_MENU', f'Menü silindi: {menu_name}')

        flash('Menü başarıyla silindi.')

    except Exception as e:
        conn.rollback()
        flash(f'Menü silinirken bir hata oluştu: {str(e)}')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_menus'))


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_users_delete(user_id):
    # Prevent self-deletion
    if user_id == session['user_id']:
        flash('Kendi hesabınızı silemezsiniz.')
        return redirect(url_for('admin_users'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get username for logging
        cursor.execute("SELECT Username FROM Users WHERE UserID = ?", (user_id,))
        username = cursor.fetchone()[0]

        # Delete user roles first
        cursor.execute("DELETE FROM UserRoles WHERE UserID = ?", (user_id,))

        # Delete password reset tokens if any
        cursor.execute("DELETE FROM PasswordResets WHERE UserID = ?", (user_id,))

        # Delete user logs
        cursor.execute("DELETE FROM UserLogs WHERE UserID = ?", (user_id,))

        # Delete user
        cursor.execute("DELETE FROM Users WHERE UserID = ?", (user_id,))

        conn.commit()

        # Log action
        log_user_action(session['user_id'], 'DELETE_USER', f'Kullanıcı silindi: {username}')

        flash('Kullanıcı başarıyla silindi.')

    except Exception as e:
        conn.rollback()
        flash(f'Kullanıcı silinirken bir hata oluştu: {str(e)}')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_users'))


@app.route('/admin/users/reset-password/<int:user_id>', methods=['POST'])
@admin_required
def admin_users_reset_password(user_id):
    # Default password to reset to
    default_password = "DefaultPassword123"  # You may want to generate a random password instead
    hashed_password = hash_password(default_password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get username for logging
        cursor.execute("SELECT Username FROM Users WHERE UserID = ?", (user_id,))
        username = cursor.fetchone()[0]

        # Update password
        cursor.execute("""
            UPDATE Users
            SET Password = ?, ModifiedDate = GETDATE()
            WHERE UserID = ?
        """, (hashed_password, user_id))

        conn.commit()

        # Log action
        log_user_action(session['user_id'], 'RESET_USER_PASSWORD', f'Kullanıcı şifresi sıfırlandı: {username}')

        flash(f'Kullanıcı şifresi başarıyla sıfırlandı. Yeni şifre: {default_password}')

    except Exception as e:
        conn.rollback()
        flash(f'Şifre sıfırlanırken bir hata oluştu: {str(e)}')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_users_edit', user_id=user_id))


@app.route('/tahsilat')
@login_required
@permission_required(menu_id=11, permission_type='view')  # Menü ID'nizi uygun şekilde ayarlayın
def tahsilat():
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    # LOGOYETKI değerini kontrol et
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT Logo, LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logo = row[0] if row and row[0] else 'HAVUZ'  # Default to 'HAVUZ' if no LOGO value found
        user_logoyetki = row[1] if row and row[1] is not None else 0  # LOGOYETKI değeri, varsayılan 0
    except Exception as e:
        flash(f'User LOGO değeri alınırken hata oluştu: {str(e)}')
        user_logo = 'HAVUZ'
        user_logoyetki = 0
    finally:
        cursor.close()
        conn.close()

    # Get tahsilat data from TIGERDB
    conn = get_db_connection2()
    cursor = conn.cursor()
    tahsilat_data = []

    try:
        cursor.execute("""
            SELECT TOP (1000) 
                [FIRMA], 
                [Cari hesap kodu], 
                [Cari hesap adı], 
                [ORT.VADE], 
                [ACIK_BORC_ORTALAMA_SÜRESı], 
                [DVZ], 
                [CARI_BAKIYE], 
                [VADESI GEÇEN TUTAR], 
                [0-7 GUN GELECEK], 
                [8-14 GUN GELECEK], 
                [15-29 GUN GELECEK], 
                [30-59 GUN GELECEK], 
                [60-89 GUN GELECEK], 
                [SAT_TEM]
            FROM [TIGERDB].[dbo].[BYT_TAHSILAT_ANALIZ_SATIS_ELEMANI_YDC_2025]
            WHERE [CARİ GRUP] IS NULL AND [SAT_TEM] IN ('HAVUZ', ?)
            ORDER BY [VADESI GEÇEN TUTAR] ASC
        """, (user_logo,))

        while True:
            row = cursor.fetchone()
            if not row:
                break

            tahsilat_data.append({
                'firma': row[0],
                'cari_hesap_kodu': row[1],
                'cari_hesap_adi': row[2],
                'ort_vade': row[3],
                'acik_borc_ortalama_sure': row[4],
                'dvz': row[5],
                'cari_bakiye': row[6],
                'vadesi_gecen_tutar': row[7],
                'gun_0_7': row[8],
                'gun_8_14': row[9],
                'gun_15_29': row[10],
                'gun_30_59': row[11],
                'gun_60_89': row[12],
                'sat_tem': row[13]
            })

    except Exception as e:
        flash(f'Tahsilat verileri alınırken hata oluştu: {str(e)}')
    finally:
        cursor.close()
        conn.close()

    return render_template('tahsilat.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           tahsilat_data=tahsilat_data,
                           user_logo=user_logo,
                           user_logoyetki=user_logoyetki,  # LOGOYETKI değerini şablona geçir
                           now=now,
                           is_admin=session.get('is_admin', False))


@app.route('/tahsilat/tum-veri')
@login_required
@permission_required(menu_id=11, permission_type='view')
def tahsilat_tum_veri():
    user_id = session['user_id']

    # LOGOYETKI kontrolü
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logoyetki = row[0] if row and row[0] is not None else 0
    finally:
        cursor.close()
        conn.close()

    # Sadece LOGOYETKI=1 olan kullanıcılar bu işlemi yapabilir
    if not user_logoyetki:
        return jsonify({'success': False, 'message': 'Bu işlem için yetkiniz bulunmamaktadır!'})

    # Tüm verileri getir (satış temsilcisi filtresi olmadan)
    conn = get_db_connection2()
    cursor = conn.cursor()
    tahsilat_data = []

    try:
        cursor.execute("""
            SELECT TOP (2000) 
                [FIRMA], 
                [Cari hesap kodu], 
                [Cari hesap adı], 
                [ORT.VADE], 
                [ACIK_BORC_ORTALAMA_SÜRESı], 
                [DVZ], 
                [CARI_BAKIYE], 
                [VADESI GEÇEN TUTAR], 
                [0-7 GUN GELECEK], 
                [8-14 GUN GELECEK], 
                [15-29 GUN GELECEK], 
                [30-59 GUN GELECEK], 
                [60-89 GUN GELECEK], 
                [SAT_TEM]
            FROM [TIGERDB].[dbo].[BYT_TAHSILAT_ANALIZ_SATIS_ELEMANI_YDC_2025]
            WHERE [CARİ GRUP] IS NULL

            ORDER BY [VADESI GEÇEN TUTAR] DESC
        """)

        while True:
            row = cursor.fetchone()
            if not row:
                break

            tahsilat_data.append([
                row[0],  # firma
                row[1],  # cari_hesap_kodu
                row[2],  # cari_hesap_adi
                row[3],  # ort_vade
                row[4],  # acik_borc_ortalama_sure
                row[5],  # dvz
                row[6],  # cari_bakiye
                row[7],  # vadesi_gecen_tutar
                row[8],  # gun_0_7
                row[9],  # gun_8_14
                row[10],  # gun_15_29
                row[11],  # gun_30_59
                row[12],  # gun_60_89
                row[13]  # sat_tem
            ])

        # Log işlemi
        log_user_action(user_id, 'TAHSILAT_TUM_VERI', 'Tüm tahsilat verileri görüntülendi')

        return jsonify({
            'success': True,
            'message': f'Toplam {len(tahsilat_data)} kayıt yüklendi.',
            'data': tahsilat_data
        })

    except Exception as e:
        return jsonify({'success': False, 'message': f'Veriler alınırken bir hata oluştu: {str(e)}'})
    finally:
        cursor.close()
        conn.close()


@app.route('/tahsilat-not')
@login_required
@permission_required(menu_id=11, permission_type='view')
def tahsilat_not():
    cari_kod = request.args.get('cari_kod')
    cari_ad = request.args.get('cari_ad')
    sat_tem = request.args.get('sat_tem')

    if not cari_kod:
        return "Cari hesap kodu gereklidir.", 400

    # Önceki notları getir - retry mechanism to avoid deadlocks
    notes = []
    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            conn = get_db_connection2()  # TIGERDB veritabanı bağlantısı
            cursor = conn.cursor()

            cursor.execute("""
                SELECT Nt_Id, Nt_Tarih, Nt_Cari, Nt_Tutar, Nt_Temsilci, Nt_Not, Nt_Cari_Kod
                FROM YH_CARI_NOTLARI
                WHERE Nt_Cari_Kod = ?
                ORDER BY Nt_Tarih DESC
            """, (cari_kod,))

            notes = []
            while True:
                row = cursor.fetchone()
                if not row:
                    break

                notes.append({
                    'id': row[0],
                    'tarih': row[1],
                    'cari': row[2],
                    'tutar': row[3],
                    'temsilci': row[4],
                    'not_text': row[5],
                    'cari_kod': row[6]
                })

            cursor.close()
            conn.close()
            break  # Success, exit the retry loop

        except Exception as e:
            if 'deadlock' in str(e).lower() and retry_count < max_retries - 1:
                # If it's a deadlock and we have retries left, wait and try again
                import time
                time.sleep(0.5)  # Wait for 500ms before retrying
                retry_count += 1
                if conn:
                    try:
                        cursor.close()
                        conn.close()
                    except:
                        pass
            else:
                # Either it's not a deadlock or we're out of retries
                print(f"Tahsilat notları alınırken hata oluştu: {str(e)}")
                if conn:
                    try:
                        cursor.close()
                        conn.close()
                    except:
                        pass
                break

    return render_template('tahsilat_not.html',
                           cari_kod=cari_kod,
                           cari_ad=cari_ad,
                           sat_tem=sat_tem,
                           notes=notes)


@app.route('/tahsilat-not-ekle', methods=['POST'])
@login_required
@permission_required(menu_id=11, permission_type='add')
def tahsilat_not_ekle():
    cari_kod = request.form.get('cari_kod')
    cari_ad = request.form.get('cari_ad')
    sat_tem = request.form.get('sat_tem')
    tutar_str = request.form.get('tutar')
    not_text = request.form.get('not_text')

    # Validate inputs
    if not cari_kod or not not_text:
        return jsonify({'success': False, 'message': 'Cari kod ve not metni gereklidir.'})

    # Convert tutar to float or None
    tutar = None
    if tutar_str and tutar_str.strip():
        try:
            tutar = float(tutar_str)
        except ValueError:
            return jsonify({'success': False, 'message': 'Geçersiz tutar formatı.'})

    # Retry mechanism for deadlocks
    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        conn = None
        try:
            # TIGERDB veritabanı bağlantısı
            conn = get_db_connection2()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO YH_CARI_NOTLARI (Nt_Tarih, Nt_Cari, Nt_Tutar, Nt_Temsilci, Nt_Not, Nt_Cari_Kod)
                VALUES (GETDATE(), ?, ?, ?, ?, ?)
            """, (cari_ad, tutar, sat_tem, not_text, cari_kod))

            conn.commit()

            # Log action (ana veritabanında)
            log_user_action(session['user_id'], 'TAHSILAT_NOT_EKLE', f'Tahsilat notu eklendi: {cari_kod}')

            cursor.close()
            conn.close()

            return jsonify({'success': True, 'message': 'Not başarıyla kaydedildi.'})

        except Exception as e:
            if conn:
                conn.rollback()

            if 'deadlock' in str(e).lower() and retry_count < max_retries - 1:
                # If it's a deadlock and we have retries left, wait and try again
                import time
                time.sleep(0.5 * (retry_count + 1))  # Exponential backoff
                retry_count += 1
                if conn:
                    try:
                        cursor.close()
                        conn.close()
                    except:
                        pass
            else:
                # Either it's not a deadlock or we're out of retries
                error_msg = str(e)
                print(f"Tahsilat notu eklenirken hata: {error_msg}")
                if conn:
                    try:
                        cursor.close()
                        conn.close()
                    except:
                        pass

                # Provide a user-friendly error message
                if 'deadlock' in error_msg.lower():
                    return jsonify({'success': False, 'message': 'Veritabanı yoğun, lütfen tekrar deneyiniz.'})
                else:
                    return jsonify({'success': False, 'message': 'Not kaydedilirken bir hata oluştu.'})


@app.route('/satis-maliyet', methods=['GET', 'POST'])
@login_required
@permission_required(menu_id=13, permission_type='view')
def satis_maliyet():
    """Satış ve Maliyet sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    # Get cari list from TIGERDB (Logo)
    cari_list = []
    try:
        conn = get_db_connection2()  # Using the TIGERDB connection
        cursor = conn.cursor()

        cursor.execute("""
            SELECT DISTINCT DEFINITION_
            FROM LG_225_CLCARD
            WHERE CYPHCODE <> 'PETROL-CH'
            ORDER BY DEFINITION_ ASC
        """)

        while True:
            row = cursor.fetchone()
            if not row:
                break

            cari_list.append({'definition': row[0]})

        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Cari listesi alınırken hata: {e}")
        # Continue even if we can't get the cari list

    # Get saved costs for the "Kaydedilmiş Maliyetler" tab
    saved_costs = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT TOP 1000 SaleID, IsEmriNo, SiparisTarihi, TeslimTarihi, 
                   Cari, Aciklama, BrutKg, FireKg, NetKg, Sure, BukumKg, 
                   VurusSayisi, AraToplam, OlusturanKullaniciID, OlusturmaTarihi,
                   KayitTipi, IsProje
            FROM Sales_Maliyet
            ORDER BY OlusturmaTarihi DESC
        """)

        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Convert date strings to datetime objects if they're not None
            siparis_tarihi = row[2]
            teslim_tarihi = row[3]
            olusturma_tarihi = row[14]

            # Format dates for display
            formatted_siparis_tarihi = siparis_tarihi.strftime('%d.%m.%Y') if siparis_tarihi and hasattr(siparis_tarihi,
                                                                                                         'strftime') else str(
                siparis_tarihi) if siparis_tarihi else ''
            formatted_teslim_tarihi = teslim_tarihi.strftime('%d.%m.%Y') if teslim_tarihi and hasattr(teslim_tarihi,
                                                                                                      'strftime') else str(
                teslim_tarihi) if teslim_tarihi else ''
            formatted_olusturma_tarihi = olusturma_tarihi.strftime('%d.%m.%Y %H:%M') if olusturma_tarihi and hasattr(
                olusturma_tarihi, 'strftime') else str(olusturma_tarihi) if olusturma_tarihi else ''

            saved_costs.append({
                'sale_id': row[0],
                'is_emri_no': row[1],
                'siparis_tarihi': formatted_siparis_tarihi,
                'teslim_tarihi': formatted_teslim_tarihi,
                'cari': row[4] or '',
                'aciklama': row[5] or '',
                'brut_kg': float(row[6]) if row[6] is not None else 0,
                'fire_kg': float(row[7]) if row[7] is not None else 0,
                'net_kg': float(row[8]) if row[8] is not None else 0,
                'sure': float(row[9]) if row[9] is not None else 0,
                'bukum_kg': float(row[10]) if row[10] is not None else 0,
                'vurus_sayisi': int(row[11]) if row[11] is not None else 0,
                'ara_toplam': float(row[12]) if row[12] is not None else 0,
                'olusturan_kullanici_id': row[13],
                'olusturma_tarihi': formatted_olusturma_tarihi,
                'kayit_tipi': row[15] or '',  # Yeni eklenen alan
                'is_proje': bool(row[16]) if row[16] is not None else False  # Yeni eklenen alan
            })
    except Exception as e:
        print(f"Kaydedilmiş maliyetler alınırken hata: {e}")

    # For POST requests (form submission)
    if request.method == 'POST':
        try:
            # Extract form data
            is_emri_no = request.form.get('is_emri_no')
            siparis_tarihi = request.form.get('siparis_tarihi')
            teslim_tarihi = request.form.get('teslim_tarihi')
            cari = request.form.get('cari')
            aciklama = request.form.get('aciklama')
            # Yeni eklenen alanlar
            kayit_tipi = request.form.get('kayit_tipi')
            is_proje = 1 if request.form.get('is_proje') else 0
            # New fields
            doviz = request.form.get('doviz') or 'TL'
            vade_yuzde = request.form.get('vade_yuzde') or 0
            vade_gun = request.form.get('vade_gun') or 0
            hesaplanan_fiyat = request.form.get('hesaplanan_fiyat') or 0
            gerceklesen_satis_fiyati = request.form.get('gerceklesen_satis_fiyati') or 0
            satis_fiyati_aciklama = request.form.get('satis_fiyati_aciklama') or ''

            # Malzeme bilgileri
            brut_kg = request.form.get('brut_kg') or 0
            fire_kg = request.form.get('fire_kg') or 0
            net_kg = request.form.get('net_kg') or 0

            # Convert time format (HH:MM:SS) to decimal hours
            sure_str = request.form.get('sure') or '00:00:00'
            sure = 0
            if sure_str:
                try:
                    # Parse the time string (HH:MM:SS)
                    parts = sure_str.split(':')
                    hours = int(parts[0])
                    minutes = int(parts[1]) if len(parts) > 1 else 0
                    seconds = int(parts[2]) if len(parts) > 2 else 0

                    # Convert to decimal hours
                    sure = hours + (minutes / 60) + (seconds / 3600)
                except:
                    sure = 0

            bukum_kg = request.form.get('bukum_kg') or 0
            vurus_sayisi = request.form.get('vurus_sayisi') or 0

            # Ara toplam
            ara_toplam = request.form.get('ara_toplam') or 0

            # Validate required fields
            if not is_emri_no:
                flash('İş Emri No alanı zorunludur.', 'error')
                return redirect(url_for('satis_maliyet'))

            # Convert string values to appropriate types
            try:
                brut_kg = float(brut_kg)
                fire_kg = float(fire_kg)
                net_kg = float(net_kg)
                bukum_kg = float(bukum_kg)
                vurus_sayisi = int(vurus_sayisi)
                ara_toplam = float(ara_toplam)
                vade_yuzde = float(vade_yuzde)
                vade_gun = int(vade_gun)
                hesaplanan_fiyat = float(hesaplanan_fiyat)
                gerceklesen_satis_fiyati = float(gerceklesen_satis_fiyati)
            except ValueError:
                flash('Sayısal değerlerde hatalı format.', 'error')
                return redirect(url_for('satis_maliyet'))

            # Database connection
            conn = get_db_connection()
            cursor = conn.cursor()

            # Insert main record with new fields
            cursor.execute("""
                INSERT INTO Sales_Maliyet (
                    IsEmriNo, SiparisTarihi, TeslimTarihi, Cari, Aciklama, 
                    BrutKg, FireKg, NetKg, Sure, BukumKg, VurusSayisi, 
                    AraToplam, OlusturanKullaniciID, Doviz, VadeYuzde,
                    VadeGun, HesaplananFiyat, GerceklesenSatisFiyati, SatisFiyatiAciklama,
                    KayitTipi, IsProje
                ) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                is_emri_no, siparis_tarihi, teslim_tarihi, cari, aciklama,
                brut_kg, fire_kg, net_kg, sure, bukum_kg, vurus_sayisi,
                ara_toplam, user_id, doviz, vade_yuzde,
                vade_gun, hesaplanan_fiyat, gerceklesen_satis_fiyati, satis_fiyati_aciklama,
                kayit_tipi, is_proje
            ))

            # Get the ID of the inserted record
            cursor.execute("SELECT @@IDENTITY")
            sale_id = cursor.fetchone()[0]

            # Process line items (Malzeme ve İşçilik)
            tur_list = request.form.getlist('tur')
            malzeme_list = request.form.getlist('malzeme')
            miktar_list = request.form.getlist('miktar')
            birim_list = request.form.getlist('birim')
            satis_birim_fiyat_list = request.form.getlist('satis_birim_fiyat')
            maliyet_birim_fiyat_list = request.form.getlist('maliyet_birim_fiyat')
            maliyet_toplam_fiyat_list = request.form.getlist('maliyet_toplam_fiyat')
            satis_toplam_fiyat_list = request.form.getlist('satis_toplam_fiyat')
            not_detay_list = request.form.getlist('not_detay')

            for i in range(len(tur_list)):
                if tur_list[i] and malzeme_list[i] and float(miktar_list[i]) > 0:
                    cursor.execute("""
                           INSERT INTO Sales_Maliyet_Detay (
                               SaleID, Tur, Malzeme, Miktar, Birim, 
                               SatisBirimFiyat, MaliyetBirimFiyat, 
                               MaliyetToplamFiyat, SatisToplamFiyat, NotDetay
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       """, (
                        sale_id,
                        tur_list[i],
                        malzeme_list[i],
                        float(miktar_list[i]),
                        birim_list[i],
                        float(satis_birim_fiyat_list[i]),
                        float(maliyet_birim_fiyat_list[i]),
                        float(maliyet_toplam_fiyat_list[i]),
                        float(satis_toplam_fiyat_list[i]),
                        not_detay_list[i]
                    ))

            conn.commit()
            # E-posta için verileri hazırla
            main_data = {
                'is_emri_no': is_emri_no,
                'siparis_tarihi': siparis_tarihi,
                'teslim_tarihi': teslim_tarihi,
                'cari': cari,
                'aciklama': aciklama,
                'brut_kg': brut_kg,
                'fire_kg': fire_kg,
                'net_kg': net_kg,
                'sure': sure_str,
                'bukum_kg': bukum_kg,
                'vurus_sayisi': vurus_sayisi,
                'ara_toplam': ara_toplam,
                'doviz': doviz,
                'vade_yuzde': vade_yuzde,
                'vade_gun': vade_gun,
                'hesaplanan_fiyat': hesaplanan_fiyat,
                'gerceklesen_satis_fiyati': gerceklesen_satis_fiyati,
                'satis_fiyati_aciklama': satis_fiyati_aciklama,
                'kayit_tipi': kayit_tipi,
                'is_proje': bool(is_proje)
            }

            # Detay verilerini hazırla
            details = []
            for i in range(len(tur_list)):
                if tur_list[i] and malzeme_list[i] and float(miktar_list[i]) > 0:
                    details.append({
                        'tur': tur_list[i],
                        'malzeme': malzeme_list[i],
                        'miktar': float(miktar_list[i]),
                        'birim': birim_list[i],
                        'satis_birim_fiyat': float(satis_birim_fiyat_list[i]),
                        'maliyet_birim_fiyat': float(maliyet_birim_fiyat_list[i]),
                        'maliyet_toplam_fiyat': float(maliyet_toplam_fiyat_list[i]),
                        'satis_toplam_fiyat': float(satis_toplam_fiyat_list[i]),
                        'not_detay': not_detay_list[i]
                    })

            email_success = False
            try:
                email_success = send_sales_cost_email(sale_id, is_emri_no, main_data, details, user_id)
                if email_success:
                    print(f"E-posta bildirimi başarıyla gönderildi: {is_emri_no}")
                else:
                    print(f"E-posta gönderilemedi: {is_emri_no}")
            except Exception as e:
                print(f"E-posta gönderilirken hata oluştu: {e}")

            # İşlem sonucunu bildir
            if email_success:
                flash('Satış ve maliyet bilgileri başarıyla kaydedildi ve e-posta gönderildi.', 'success')
            else:
                # E-posta gönderilemediyse bile veritabanı işlemi başarılı olduğu için ana mesaj olumlu
                flash('Satış ve maliyet bilgileri başarıyla kaydedildi.', 'success')
                # Ek bir uyarı mesajı göster
                flash('Bilgilendirme e-postası gönderilemedi.', 'warning')

            # Log the action
            log_user_action(user_id, 'SATIS_MALIYET_KAYDET', f'Satış ve maliyet kaydedildi: {is_emri_no}')

            flash('Satış ve maliyet bilgileri başarıyla kaydedildi.', 'success')
            return redirect(url_for('satis_maliyet'))

        except Exception as e:
            # If any error occurs, rollback the transaction
            if 'conn' in locals() and conn:
                conn.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'error')
            print(f"Satış ve maliyet kaydederken hata: {e}")
            return redirect(url_for('satis_maliyet'))
        finally:
            # Close database connections
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'conn' in locals() and conn:
                conn.close()

        # For GET requests (form display)
    return render_template('satis_maliyet.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           now=now,
                           cari_list=cari_list,
                           saved_costs=saved_costs)


@app.route('/satis-maliyet/details/<int:sale_id>')
@login_required
def satis_maliyet_details(sale_id):
    """Satış ve maliyet detaylarını göster."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get main record with new fields
        cursor.execute("""
            SELECT SaleID, IsEmriNo, SiparisTarihi, TeslimTarihi, 
                   Cari, Aciklama, BrutKg, FireKg, NetKg, Sure, BukumKg, 
                   VurusSayisi, AraToplam, OlusturanKullaniciID, OlusturmaTarihi,
                   Doviz, VadeYuzde, VadeGun, HesaplananFiyat, GerceklesenSatisFiyati, SatisFiyatiAciklama,
                   KayitTipi, IsProje
            FROM Sales_Maliyet
            WHERE SaleID = ?
        """, (sale_id,))

        main_data = cursor.fetchone()

        if not main_data:
            return "<div class='alert alert-warning'>Kayıt bulunamadı!</div>"

        # Format the time from decimal hours to HH:MM:SS
        sure_decimal = main_data[9] or 0
        sure_hours = int(sure_decimal)
        sure_minutes = int((sure_decimal - sure_hours) * 60)
        sure_seconds = int(((sure_decimal - sure_hours) * 60 - sure_minutes) * 60)
        sure_formatted = f"{sure_hours:02}:{sure_minutes:02}:{sure_seconds:02}"

        # Format dates for display
        siparis_tarihi = main_data[2]
        teslim_tarihi = main_data[3]
        olusturma_tarihi = main_data[14]

        formatted_siparis_tarihi = siparis_tarihi.strftime('%d.%m.%Y') if siparis_tarihi and hasattr(siparis_tarihi,
                                                                                                     'strftime') else str(
            siparis_tarihi) if siparis_tarihi else ''
        formatted_teslim_tarihi = teslim_tarihi.strftime('%d.%m.%Y') if teslim_tarihi and hasattr(teslim_tarihi,
                                                                                                  'strftime') else str(
            teslim_tarihi) if teslim_tarihi else ''
        formatted_olusturma_tarihi = olusturma_tarihi.strftime('%d.%m.%Y %H:%M') if olusturma_tarihi and hasattr(
            olusturma_tarihi, 'strftime') else str(olusturma_tarihi) if olusturma_tarihi else ''

        # Get detail records
        cursor.execute("""
            SELECT DetayID, SaleID, Tur, Malzeme, Miktar, Birim, 
                   SatisBirimFiyat, MaliyetBirimFiyat, 
                   MaliyetToplamFiyat, SatisToplamFiyat, NotDetay
            FROM Sales_Maliyet_Detay
            WHERE SaleID = ?
            ORDER BY DetayID
        """, (sale_id,))

        details = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            details.append({
                'detay_id': row[0],
                'sale_id': row[1],
                'tur': row[2],
                'malzeme': row[3],
                'miktar': float(row[4]) if row[4] is not None else 0,
                'birim': row[5] if row[5] else 'KG',  # Default to KG if not set
                'satis_birim_fiyat': float(row[6]) if row[6] is not None else 0,
                'maliyet_birim_fiyat': float(row[7]) if row[7] is not None else 0,
                'maliyet_toplam_fiyat': float(row[8]) if row[8] is not None else 0,
                'satis_toplam_fiyat': float(row[9]) if row[9] is not None else 0,
                'not_detay': row[10] or ''
            })

        # Get info about creator
        username = "Bilinmiyor"
        if main_data[13]:  # OlusturanKullaniciID
            cursor.execute("SELECT Username FROM Users WHERE UserID = ?", (main_data[13],))
            user_row = cursor.fetchone()
            if user_row:
                username = user_row[0]

        cursor.close()
        conn.close()

        # Convert main_data to a dictionary for easier template rendering
        main = {
            'sale_id': main_data[0],
            'is_emri_no': main_data[1],
            'siparis_tarihi': formatted_siparis_tarihi,
            'teslim_tarihi': formatted_teslim_tarihi,
            'cari': main_data[4] or '',
            'aciklama': main_data[5] or '',
            'brut_kg': float(main_data[6]) if main_data[6] is not None else 0,
            'fire_kg': float(main_data[7]) if main_data[7] is not None else 0,
            'net_kg': float(main_data[8]) if main_data[8] is not None else 0,
            'sure': sure_formatted,
            'bukum_kg': float(main_data[10]) if main_data[10] is not None else 0,
            'vurus_sayisi': int(main_data[11]) if main_data[11] is not None else 0,
            'ara_toplam': float(main_data[12]) if main_data[12] is not None else 0,
            'olusturan_kullanici': username,
            'olusturma_tarihi': formatted_olusturma_tarihi,
            # New fields
            'doviz': main_data[15] or 'TL',
            'vade_yuzde': float(main_data[16]) if main_data[16] is not None else 0,
            'vade_gun': int(main_data[17]) if main_data[17] is not None else 0,
            'hesaplanan_fiyat': float(main_data[18]) if main_data[18] is not None else 0,
            'gerceklesen_satis_fiyati': float(main_data[19]) if main_data[19] is not None else 0,
            'satis_fiyati_aciklama': main_data[20] or '',
            'kayit_tipi': main_data[21] or '',
            'is_proje': bool(main_data[22]) if main_data[22] is not None else False
        }

        # Render template as a partial for the modal content
        return render_template('satis_maliyet_details_partial.html', main=main, details=details)

    except Exception as e:
        print(f"Maliyet detayları alınırken hata: {e}")
        return f"<div class='alert alert-danger'>Detaylar yüklenirken bir hata oluştu: {str(e)}</div>"


@app.route('/satis-maliyet/delete/<int:sale_id>', methods=['POST'])
@login_required
@permission_required(menu_id=13, permission_type='delete')
def satis_maliyet_delete(sale_id):
    """Satış ve maliyet kaydını sil."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # First check if the record exists
        cursor.execute("SELECT IsEmriNo FROM Sales_Maliyet WHERE SaleID = ?", (sale_id,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'success': False, 'message': 'Kayıt bulunamadı!'})

        is_emri_no = row[0]

        # Delete detail records first (cascading delete if foreign key constraints are set up properly)
        cursor.execute("DELETE FROM Sales_Maliyet_Detay WHERE SaleID = ?", (sale_id,))

        # Delete main record
        cursor.execute("DELETE FROM Sales_Maliyet WHERE SaleID = ?", (sale_id,))

        conn.commit()

        # Log the action
        log_user_action(session['user_id'], 'SATIS_MALIYET_SIL', f'Satış ve maliyet silindi: {is_emri_no}')

        return jsonify({'success': True, 'message': 'Kayıt başarıyla silindi.'})

    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        print(f"Maliyet kaydı silinirken hata: {e}")
        return jsonify({'success': False, 'message': f'Kayıt silinirken bir hata oluştu: {str(e)}'})
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()


@app.route('/satis-maliyet/edit/<int:sale_id>', methods=['GET', 'POST'])
@login_required
@permission_required(menu_id=13, permission_type='edit')
def satis_maliyet_edit(sale_id):
    """Satış ve maliyet kaydını düzenle."""
    # This route would be implemented with similar logic to the main route,
    # but for editing existing records instead of creating new ones.
    # For now, we'll include a placeholder that redirects to the main page
    flash('Düzenleme özelliği henüz uygulanmamıştır.', 'warning')
    return redirect(url_for('satis_maliyet'))


# 3. Satış ve Maliyet Detayları E-postası (paste-3.txt'den)
def send_sales_cost_email(sale_id, is_emri_no, main_data, details, user_id):
    """Satış ve maliyet detaylarını e-posta ile gönderir."""
    try:
        # Kullanıcı bilgilerini almak için veritabanı bağlantısı
        conn = get_db_connection()
        cursor = conn.cursor()

        # Kullanıcının FullName bilgisini al
        cursor.execute("SELECT FullName FROM Users WHERE UserID = ?", (user_id,))
        user_row = cursor.fetchone()
        user_fullname = user_row[0] if user_row else "Bilinmiyor"

        cursor.close()
        conn.close()

        # Gmail SMTP ayarları
        sender_email = "yagcilarholding1@gmail.com"
        sender_password = "bqnp sius nztz padc"

        # Birden fazla alıcı için liste oluştur
        recipients = ["dogukanturan@ydcmetal.com.tr", "veli@staryagcilar.com.tr"]

        # E-posta konteyneri oluştur
        msg = MIMEMultipart('alternative')
        msg['From'] = sender_email
        msg['To'] = ", ".join(recipients)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = f"Yeni Satış ve Maliyet Kaydı: {is_emri_no}"

        # HTML içeriği oluştur
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ width: 100%; max-width: 800px; margin: 0 auto; }}
                h1, h2 {{ color: #0056b3; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th, td {{ padding: 10px; text-align: left; border: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; font-weight: bold; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .header {{ background-color: #0056b3; color: white; padding: 10px; margin-bottom: 20px; text-align: center; }}
                .footer {{ background-color: #f2f2f2; padding: 10px; font-size: 12px; text-align: center; margin-top: 20px; }}
                .summary-value {{ font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Yeni Satış ve Maliyet Kaydı</h1>
                    <p>İş Emri No: {main_data.get('is_emri_no', '')}</p>
                </div>

                <h2>Özet Bilgiler</h2>
                <table>
                    <tr>
                        <th style="width: 25%;">İş Emri No</th>
                        <td style="width: 25%;" class="summary-value">{main_data.get('is_emri_no', '')}</td>
                        <th style="width: 25%;">Kayıt Tipi</th>
                        <td style="width: 25%;" class="summary-value">{main_data.get('kayit_tipi', '')}</td>
                    </tr>
                    <tr>
                        <th>Sipariş Tarihi</th>
                        <td class="summary-value">{main_data.get('siparis_tarihi', '')}</td>
                        <th>Teslim Tarihi</th>
                        <td class="summary-value">{main_data.get('teslim_tarihi', '')}</td>
                    </tr>
                    <tr>
                        <th>Cari</th>
                        <td class="summary-value">{main_data.get('cari', '')}</td>
                        <th>Proje Mi?</th>
                        <td class="summary-value">{'Evet' if main_data.get('is_proje') else 'Hayır'}</td>
                    </tr>
                    <tr>
                        <th>Açıklama</th>
                        <td colspan="3" class="summary-value">{main_data.get('aciklama', '')}</td>
                    </tr>
                    <tr>
                        <th>Brüt KG</th>
                        <td class="summary-value">{main_data.get('brut_kg', 0)}</td>
                        <th>Fire KG</th>
                        <td class="summary-value">{main_data.get('fire_kg', 0)}</td>
                    </tr>
                    <tr>
                        <th>Net KG</th>
                        <td class="summary-value">{main_data.get('net_kg', 0)}</td>
                        <th>Büküm KG</th>
                        <td class="summary-value">{main_data.get('bukum_kg', 0)}</td>
                    </tr>
                    <tr>
                        <th>Süre</th>
                        <td class="summary-value">{main_data.get('sure', '')}</td>
                        <th>Vuruş Sayısı</th>
                        <td class="summary-value">{main_data.get('vurus_sayisi', 0)}</td>
                    </tr>
                    <tr>
                        <th>Döviz</th>
                        <td class="summary-value">{main_data.get('doviz', 'TL')}</td>
                        <th>Vade (%)</th>
                        <td class="summary-value">{main_data.get('vade_yuzde', 0)}</td>
                    </tr>
                    <tr>
                        <th>Vade (Gün)</th>
                        <td class="summary-value">{main_data.get('vade_gun', 0)}</td>
                        <th>Ara Toplam</th>
                        <td class="summary-value">{main_data.get('ara_toplam', 0)}</td>
                    </tr>
                    <tr>
                        <th>Hesaplanan Fiyat</th>
                        <td class="summary-value">{main_data.get('hesaplanan_fiyat', 0)}</td>
                        <th>Gerçekleşen Satış Fiyatı</th>
                        <td class="summary-value">{main_data.get('gerceklesen_satis_fiyati', 0)}</td>
                    </tr>
                    <tr>
                        <th>Oluşturan Kullanıcı</th>
                        <td colspan="3" class="summary-value">{user_fullname}</td>
                    </tr>
                </table>

                <h2>Detay Bilgiler</h2>
                <table>
                    <tr>
                        <th>Tür</th>
                        <th>Malzeme</th>
                        <th>Miktar</th>
                        <th>Birim</th>
                        <th>Maliyet Birim</th>
                        <th>Maliyet Toplam</th>
                        <th>Satış Birim</th>
                        <th>Satış Toplam</th>
                    </tr>
        """

        # Detay satırları ekle
        for detail in details:
            html += f"""
                    <tr>
                        <td>{detail.get('tur', '')}</td>
                        <td>{detail.get('malzeme', '')}</td>
                        <td>{detail.get('miktar', 0)}</td>
                        <td>{detail.get('birim', '')}</td>
                        <td>{detail.get('maliyet_birim_fiyat', 0)}</td>
                        <td>{detail.get('maliyet_toplam_fiyat', 0)}</td>
                        <td>{detail.get('satis_birim_fiyat', 0)}</td>
                        <td>{detail.get('satis_toplam_fiyat', 0)}</td>
                    </tr>
            """

        # HTML'i kapat
        html += """
                </table>

                <div class="footer">
                    <p>Bu e-posta otomatik olarak oluşturulmuştur. Lütfen yanıtlamayınız.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # HTML içeriği ekle
        msg.attach(MIMEText(html, 'html'))

        # Gmail SMTP sunucusuna bağlan
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Gmail için TLS gerekli
        server.login(sender_email, sender_password)

        # E-postayı her iki alıcıya da gönder
        server.sendmail(sender_email, recipients, msg.as_string())
        server.quit()

        print(f"E-posta başarıyla gönderildi: {', '.join(recipients)}")
        return True
    except Exception as e:
        print(f"E-posta gönderilirken hata oluştu: {e}")
        return False


@app.route('/maliyet-veri')
@login_required
@permission_required(menu_id=12, permission_type='view')  # Adjust menu_id based on your menu structure
def maliyet_veri():
    """Maliyet veri sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    # Get sales data with cost status
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT 
                s.SaleID, 
                s.IsEmriNo, 
                s.SiparisTarihi, 
                s.TeslimTarihi, 
                s.Cari, 
                s.Aciklama, 
                s.BrutKg, 
                s.NetKg, 
                s.AraToplam as SatisTutari,
                CASE WHEN c.CostID IS NULL THEN 0 ELSE 1 END as MaliyetGirildi,
                c.AraToplam as MaliyetTutari,
                c.CostID,
                s.IsProje
            FROM 
                Sales_Maliyet s
            LEFT JOIN 
                Cost_Maliyet c ON s.SaleID = c.SaleID
            ORDER BY 
                s.OlusturmaTarihi DESC
        """)

        sales_data = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Format dates for display
            siparis_tarihi = row[2]
            teslim_tarihi = row[3]

            formatted_siparis_tarihi = siparis_tarihi.strftime('%d.%m.%Y') if siparis_tarihi and hasattr(siparis_tarihi,
                                                                                                         'strftime') else str(
                siparis_tarihi) if siparis_tarihi else ''
            formatted_teslim_tarihi = teslim_tarihi.strftime('%d.%m.%Y') if teslim_tarihi and hasattr(teslim_tarihi,
                                                                                                      'strftime') else str(
                teslim_tarihi) if teslim_tarihi else ''

            sales_data.append({
                'sale_id': row[0],
                'is_emri_no': row[1],
                'siparis_tarihi': formatted_siparis_tarihi,
                'teslim_tarihi': formatted_teslim_tarihi,
                'cari': row[4] or '',
                'aciklama': row[5] or '',
                'brut_kg': float(row[6]) if row[6] is not None else 0,
                'net_kg': float(row[7]) if row[7] is not None else 0,
                'satis_tutari': float(row[8]) if row[8] is not None else 0,
                'maliyet_girildi': row[9] == 1,
                'maliyet_tutari': float(row[10]) if row[10] is not None else 0,
                'cost_id': row[11],
                'is_proje': bool(row[12]) if row[12] is not None else False
            })

    except Exception as e:
        flash(f'Satış verileri alınırken bir hata oluştu: {str(e)}', 'error')
        sales_data = []
    finally:
        cursor.close()
        conn.close()

    return render_template('maliyet_veri.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           sales_data=sales_data,
                           now=now)


@app.route('/maliyet-veri/details/<int:sale_id>')
@login_required
@permission_required(menu_id=12, permission_type='view')
def maliyet_veri_details(sale_id):
    """Maliyet veri detaylarını göster ve düzenleme sağla."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get main sales record with additional fields
        cursor.execute("""
            SELECT 
                s.SaleID, 
                s.IsEmriNo, 
                s.SiparisTarihi, 
                s.TeslimTarihi, 
                s.Cari, 
                s.Aciklama, 
                s.BrutKg, 
                s.FireKg, 
                s.NetKg, 
                s.Sure, 
                s.BukumKg, 
                s.VurusSayisi, 
                s.AraToplam as SatisTutari,
                c.CostID,
                c.AraToplam as MaliyetTutari,
                c.Aciklama as MaliyetAciklama,
                s.Doviz,
                s.VadeYuzde,
                s.VadeGun,
                s.HesaplananFiyat,
                s.GerceklesenSatisFiyati,
                s.SatisFiyatiAciklama,
                c.GerceklesenMaliyetFiyati,
                c.MaliyetFiyatiAciklama,
                c.VadeGun as MaliyetVadeGun,
                s.IsProje
            FROM 
                Sales_Maliyet s
            LEFT JOIN 
                Cost_Maliyet c ON s.SaleID = c.SaleID
            WHERE 
                s.SaleID = ?
        """, (sale_id,))

        main_row = cursor.fetchone()

        if not main_row:
            flash('Satış kaydı bulunamadı!', 'error')
            return redirect(url_for('maliyet_veri'))

        # Format the time from decimal hours to HH:MM:SS
        sure_decimal = main_row[9] or 0
        sure_hours = int(sure_decimal)
        sure_minutes = int((sure_decimal - sure_hours) * 60)
        sure_seconds = int(((sure_decimal - sure_hours) * 60 - sure_minutes) * 60)
        sure_formatted = f"{sure_hours:02}:{sure_minutes:02}:{sure_seconds:02}"

        # Format dates for display
        siparis_tarihi = main_row[2]
        teslim_tarihi = main_row[3]

        formatted_siparis_tarihi = siparis_tarihi.strftime('%d.%m.%Y') if siparis_tarihi and hasattr(siparis_tarihi,
                                                                                                     'strftime') else str(
            siparis_tarihi) if siparis_tarihi else ''
        formatted_teslim_tarihi = teslim_tarihi.strftime('%d.%m.%Y') if teslim_tarihi and hasattr(teslim_tarihi,
                                                                                                  'strftime') else str(
            teslim_tarihi) if teslim_tarihi else ''

        # Get sales detail records
        cursor.execute("""
            SELECT DetayID, SaleID, Tur, Malzeme, Miktar, Birim, SatisBirimFiyat, SatisToplamFiyat
            FROM Sales_Maliyet_Detay
            WHERE SaleID = ?
            ORDER BY DetayID
        """, (sale_id,))

        sales_details = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            sales_details.append({
                'detay_id': row[0],
                'sale_id': row[1],
                'tur': row[2],
                'malzeme': row[3],
                'miktar': float(row[4]) if row[4] is not None else 0,
                'birim': row[5] if row[5] else 'KG',
                'birim_fiyat': float(row[6]) if row[6] is not None else 0,
                'toplam_fiyat': float(row[7]) if row[7] is not None else 0
            })

        # Get cost detail records if cost exists
        cost_details = []
        cost_id = main_row[13]  # CostID from the main query
        maliyet_girildi = cost_id is not None

        if cost_id:
            cursor.execute("""
                SELECT MaliyetDetayID, CostID, Tur, Malzeme, Miktar, Birim, BirimMaliyet, ToplamMaliyet
                FROM Cost_Maliyet_Detay
                WHERE CostID = ?
                ORDER BY MaliyetDetayID
            """, (cost_id,))

            while True:
                row = cursor.fetchone()
                if not row:
                    break

                cost_details.append({
                    'maliyet_detay_id': row[0],
                    'cost_id': row[1],
                    'tur': row[2],
                    'malzeme': row[3],
                    'miktar': float(row[4]) if row[4] is not None else 0,
                    'birim': row[5] if row[5] else 'KG',
                    'birim_maliyet': float(row[6]) if row[6] is not None else 0,
                    'toplam_maliyet': float(row[7]) if row[7] is not None else 0
                })

        cursor.close()
        conn.close()

        # Use maliyet_vade_gun if available, otherwise use the sales vade_gun
        vade_gun = main_row[24] if main_row[24] is not None else main_row[18]

        # Build the data structure for the template
        main_data = {
            'sale_id': main_row[0],
            'is_emri_no': main_row[1],
            'siparis_tarihi': formatted_siparis_tarihi,
            'teslim_tarihi': formatted_teslim_tarihi,
            'cari': main_row[4] or '',
            'aciklama': main_row[5] or '',
            'brut_kg': float(main_row[6]) if main_row[6] is not None else 0,
            'fire_kg': float(main_row[7]) if main_row[7] is not None else 0,
            'net_kg': float(main_row[8]) if main_row[8] is not None else 0,
            'sure': sure_formatted,
            'bukum_kg': float(main_row[10]) if main_row[10] is not None else 0,
            'vurus_sayisi': int(main_row[11]) if main_row[11] is not None else 0,
            'satis_tutari': float(main_row[12]) if main_row[12] is not None else 0,
            'cost_id': main_row[13],
            'maliyet_tutari': float(main_row[14]) if main_row[14] is not None else 0,
            'maliyet_aciklama': main_row[15] or '',
            'doviz': main_row[16] or 'TL',
            'vade_yuzde': float(main_row[17]) if main_row[17] is not None else 0,
            'vade_gun': vade_gun,  # Burada artık doğru vade gün değerini kullanıyoruz
            'hesaplanan_fiyat': float(main_row[19]) if main_row[19] is not None else 0,
            'gerceklesen_satis_fiyati': float(main_row[20]) if main_row[20] is not None else 0,
            'satis_fiyati_aciklama': main_row[21] or '',
            'gerceklesen_maliyet_fiyati': float(main_row[22]) if main_row[22] is not None else 0,
            'maliyet_fiyati_aciklama': main_row[23] or '',
            'is_proje': bool(main_row[25]) if main_row[25] is not None else False
        }

        return render_template('maliyet_veri_details.html',
                               username=session['username'],
                               fullname=session.get('fullname', ''),
                               main_data=main_data,
                               sales_details=sales_details,
                               cost_details=cost_details,
                               maliyet_girildi=maliyet_girildi)

    except Exception as e:
        print(f"Maliyet veri detayları alınırken hata: {e}")
        flash(f'Detay bilgileri alınırken bir hata oluştu: {str(e)}', 'error')
        return redirect(url_for('maliyet_veri'))


@app.route('/maliyet-veri/save/<int:sale_id>', methods=['POST'])
@login_required
@permission_required(menu_id=12, permission_type='add')
def maliyet_veri_save(sale_id):
    """Maliyet bilgilerini kaydet."""
    try:
        # Get form data
        maliyet_toplam = request.form.get('maliyet_toplam')
        maliyet_aciklama = request.form.get('maliyet_aciklama', '')

        # Form fields
        maliyet_fiyati_aciklama = request.form.get('maliyet_fiyati_aciklama', '')
        gerceklesen_maliyet_fiyati = request.form.get('gerceklesen_maliyet_fiyati', 0)
        vade_gun = request.form.get('vade_gun', 0)

        # Extract detail items
        tur_list = request.form.getlist('tur')
        malzeme_list = request.form.getlist('malzeme')
        miktar_list = request.form.getlist('miktar')
        birim_list = request.form.getlist('birim')
        birim_maliyet_list = request.form.getlist('birim_maliyet')
        toplam_maliyet_list = request.form.getlist('toplam_maliyet')

        # Convert to appropriate types
        try:
            maliyet_toplam = float(maliyet_toplam)
            gerceklesen_maliyet_fiyati = float(gerceklesen_maliyet_fiyati)
            vade_gun = int(vade_gun)
        except ValueError:
            maliyet_toplam = 0
            gerceklesen_maliyet_fiyati = 0
            vade_gun = 0

        # Get current user
        user_id = session['user_id']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Get currency and other info from sales record
        cursor.execute("SELECT Doviz, VadeYuzde, HesaplananFiyat FROM Sales_Maliyet WHERE SaleID = ?", (sale_id,))
        sales_data = cursor.fetchone()
        doviz = sales_data[0] if sales_data and sales_data[0] else 'TL'
        vade_yuzde = sales_data[1] if sales_data and sales_data[1] is not None else 0
        hesaplanan_fiyat = sales_data[2] if sales_data and sales_data[2] is not None else 0

        # Check if cost record already exists
        cursor.execute("SELECT CostID FROM Cost_Maliyet WHERE SaleID = ?", (sale_id,))
        existing_cost = cursor.fetchone()

        try:
            if existing_cost:
                # Update existing cost record
                cost_id = existing_cost[0]
                cursor.execute("""
                    UPDATE Cost_Maliyet
                    SET AraToplam = ?, Aciklama = ?, OlusturanKullaniciID = ?, OlusturmaTarihi = GETDATE(),
                        Doviz = ?, VadeYuzde = ?, VadeGun = ?, HesaplananFiyat = ?,
                        GerceklesenMaliyetFiyati = ?, MaliyetFiyatiAciklama = ?
                    WHERE CostID = ?
                """, (maliyet_toplam, maliyet_aciklama, user_id,
                      doviz, vade_yuzde, vade_gun, hesaplanan_fiyat,
                      gerceklesen_maliyet_fiyati, maliyet_fiyati_aciklama, cost_id))

                # Delete existing detail records
                cursor.execute("DELETE FROM Cost_Maliyet_Detay WHERE CostID = ?", (cost_id,))
            else:
                # Create new cost record
                cursor.execute("""
                    INSERT INTO Cost_Maliyet (
                        SaleID, AraToplam, Aciklama, OlusturanKullaniciID,
                        Doviz, VadeYuzde, VadeGun, HesaplananFiyat,
                        GerceklesenMaliyetFiyati, MaliyetFiyatiAciklama
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (sale_id, maliyet_toplam, maliyet_aciklama, user_id,
                      doviz, vade_yuzde, vade_gun, hesaplanan_fiyat,
                      gerceklesen_maliyet_fiyati, maliyet_fiyati_aciklama))

                # Get the ID of the inserted record
                cursor.execute("SELECT @@IDENTITY")
                cost_id = cursor.fetchone()[0]

            # Insert detail records
            for i in range(len(tur_list)):
                if tur_list[i] and malzeme_list[i]:
                    try:
                        miktar = float(miktar_list[i])
                        birim_maliyet = float(birim_maliyet_list[i])
                        toplam_maliyet = float(toplam_maliyet_list[i])
                    except (ValueError, IndexError):
                        miktar = 0
                        birim_maliyet = 0
                        toplam_maliyet = 0

                    cursor.execute("""
                        INSERT INTO Cost_Maliyet_Detay (
                            CostID, Tur, Malzeme, Miktar, Birim, BirimMaliyet, ToplamMaliyet
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cost_id,
                        tur_list[i],
                        malzeme_list[i],
                        miktar,
                        birim_list[i] if i < len(birim_list) else 'KG',
                        birim_maliyet,
                        toplam_maliyet
                    ))

            conn.commit()

            # Log the action
            log_user_action(user_id, 'MALIYET_KAYDET', f'Maliyet bilgileri kaydedildi: SaleID={sale_id}')

            return jsonify({'success': True, 'message': 'Maliyet bilgileri başarıyla kaydedildi.'})

        except Exception as e:
            conn.rollback()
            print(f"Maliyet bilgileri kaydedilirken hata: {e}")
            return jsonify({'success': False, 'message': f'Maliyet bilgileri kaydedilirken bir hata oluştu: {str(e)}'})
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Maliyet bilgileri kaydedilirken genel hata: {e}")
        return jsonify({'success': False, 'message': f'İşlem sırasında bir hata oluştu: {str(e)}'})


@app.route('/stok-listesi')
@login_required
@permission_required(menu_id=14, permission_type='view')  # Adjust menu_id based on your menu structure
def stok_listesi():
    """Stok listesi sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    return render_template('stok_listesi.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           now=now)


@app.route('/stok-listesi/data')
@login_required
def stok_listesi_data():
    """Stok listesi verilerini getir."""
    try:
        conn = get_db_connection3()  # MikroDB_V16_10 veritabanı bağlantısı
        cursor = conn.cursor()

        # Stok listesi verilerini çek
        cursor.execute("""
            SELECT 
                [ANA GRUP] AS ANA_GRUP,
                [ALT GRUP] AS ALT_GRUP,
                [STOK ADI] AS STOK_ADI,
                [KALINLIK] AS KALINLIK,
                [YÜKSEKLİK] AS YUKSEKLIK,
                [EN] AS EN,
                [BOY] AS BOY,
                [KALİTE] AS KALITE,
                [2.KALİTE] AS KALITE2,
                [DEPO (ADET)] AS DEPO_ADET,
                [REZERVE (ADET)] AS REZERVE_ADET,
                [TOP.MİKTAR (ADET)] AS TOPLAM_MIKTAR_ADET,
                [TOP.MİKTAR (KG)] AS TOPLAM_MIKTAR_KG,
                [NOT] AS NOTLAR
            FROM [dbo].[_YH_STOK_LISTESI]
            ORDER BY [ANA GRUP], [ALT GRUP], [STOK ADI]
        """)

        # Verileri JSON formatına dönüştür
        stok_data = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            stok_data.append({
                'ANA_GRUP': row[0] if row[0] else '',
                'ALT_GRUP': row[1] if row[1] else '',
                'STOK_ADI': row[2] if row[2] else '',
                'KALINLIK': row[3] if row[3] else '',
                'YUKSEKLIK': row[4] if row[4] else '',
                'EN': row[5] if row[5] else '',
                'BOY': row[6] if row[6] else '',
                'KALITE': row[7] if row[7] else '',
                'KALITE2': row[8] if row[8] else '',
                'DEPO_ADET': float(row[9]) if row[9] is not None else 0,
                'REZERVE_ADET': float(row[10]) if row[10] is not None else 0,
                'TOPLAM_MIKTAR_ADET': float(row[11]) if row[11] is not None else 0,
                'TOPLAM_MIKTAR_KG': float(row[12]) if row[12] is not None else 0,
                'NOT': row[13] if row[13] else ''
            })

        cursor.close()
        conn.close()

        # Log action
        log_user_action(session['user_id'], 'STOK_LISTESI_GORUNTULE', 'Stok listesi görüntülendi')

        return jsonify(stok_data)

    except Exception as e:
        print(f"Stok listesi verileri alınırken hata: {e}")
        return jsonify([])  # Hata durumunda boş liste dön

    # Add this route to app.py


@app.route('/fatura-onay')
@login_required
@permission_required(menu_id=16, permission_type='view')
def fatura_onay():
    """Fatura onay sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    # Check user's permission level
    is_admin = session.get('is_admin', False)
    user_logoyetki = 0

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get LogoYetki value for the current user
        cursor.execute("SELECT LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logoyetki = row[0] if row and row[0] is not None else 0
    except Exception as e:
        flash(f'Kullanıcı yetkileri alınırken hata oluştu: {str(e)}', 'error')
    finally:
        cursor.close()

    # Get cari list from TIGERDB
    cari_list = []
    try:
        conn = get_db_connection2()  # Using the TIGERDB connection
        cursor = conn.cursor()

        cursor.execute("""
            SELECT DISTINCT DEFINITION_
            FROM LG_225_CLCARD
            WHERE CYPHCODE <> 'PETROL-CH'
            ORDER BY DEFINITION_ ASC
        """)

        while True:
            row = cursor.fetchone()
            if not row:
                break

            cari_list.append({'definition': row[0]})

        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Cari listesi alınırken hata: {e}")
        # Continue even if we can't get the cari list

    # Based on permissions, get the appropriate data
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Admins and users with LogoYetki=1 can see all records
        if is_admin or user_logoyetki == 1:
            cursor.execute("""
                SELECT 
                    f.FaturaID, 
                    f.FaturaNo, 
                    f.Tarih, 
                    f.Firma, 
                    f.Vade, 
                    f.OlusturanKullaniciID,
                    u.FullName as OlusturanKullaniciAd,
                    u.Username as OlusturanKullanici,
                    f.OdemeYapildi,
                    CASE WHEN f.OdemeYapildi = 1 THEN 'Ödendi' ELSE 'Ödeme Bekliyor' END as OdemeDurumu,
                    f.OdemeTarihi,
                    f.OnaylayanKullaniciID,
                    o.FullName as OnaylayanKullaniciAd,
                    o.Username as OnaylayanKullanici,
                    f.Notlar,
                    f.CariIsmi
                FROM 
                    FaturaOnay f
                JOIN 
                    Users u ON f.OlusturanKullaniciID = u.UserID
                LEFT JOIN 
                    Users o ON f.OnaylayanKullaniciID = o.UserID
                ORDER BY 
                    f.Tarih DESC
            """)
        else:
            # Regular users can only see their own records
            cursor.execute("""
                SELECT 
                    f.FaturaID, 
                    f.FaturaNo, 
                    f.Tarih, 
                    f.Firma, 
                    f.Vade, 
                    f.OlusturanKullaniciID,
                    u.FullName as OlusturanKullaniciAd,
                    u.Username as OlusturanKullanici,
                    f.OdemeYapildi,
                    CASE WHEN f.OdemeYapildi = 1 THEN 'Ödendi' ELSE 'Ödeme Bekliyor' END as OdemeDurumu,
                    f.OdemeTarihi,
                    f.OnaylayanKullaniciID,
                    o.FullName as OnaylayanKullaniciAd,
                    o.Username as OnaylayanKullanici,
                    f.Notlar,
                    f.CariIsmi
                FROM 
                    FaturaOnay f
                JOIN 
                    Users u ON f.OlusturanKullaniciID = u.UserID
                LEFT JOIN 
                    Users o ON f.OnaylayanKullaniciID = o.UserID
                WHERE 
                    f.OlusturanKullaniciID = ?
                ORDER BY 
                    f.Tarih DESC
            """, (user_id,))

        faturalar = []
        cari_list_unique = set()  # Tekil cari isimlerini tutacak set

        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Format date
            tarih = row[2]
            formatted_tarih = tarih.strftime('%d.%m.%Y') if tarih and hasattr(tarih, 'strftime') else str(
                tarih) if tarih else ''

            # Format payment date if exists
            odeme_tarihi = row[10]
            formatted_odeme_tarihi = odeme_tarihi.strftime('%d.%m.%Y') if odeme_tarihi and hasattr(odeme_tarihi,
                                                                                                   'strftime') else ''

            # Cari ismi değerini al ve boş değilse listeye ekle
            cari_ismi = row[15] or ''
            if cari_ismi:
                cari_list_unique.add(cari_ismi)

            faturalar.append({
                'fatura_id': row[0],
                'fatura_no': row[1],
                'tarih': formatted_tarih,
                'firma': row[3],
                'vade': row[4],
                'olusturan_kullanici_id': row[5],
                'olusturan_kullanici_ad': row[6] or row[7],  # Use FullName if available, otherwise Username
                'odeme_yapildi': row[8],
                'odeme_durumu': row[9],
                'odeme_tarihi': formatted_odeme_tarihi,
                'onaylayan_kullanici_id': row[11],
                'onaylayan_kullanici': row[12] or row[13],  # Use FullName if available, otherwise Username
                'notlar': row[14],
                'cari_ismi': cari_ismi
            })

    except Exception as e:
        flash(f'Fatura verileri alınırken bir hata oluştu: {str(e)}', 'error')
        faturalar = []
        cari_list_unique = set()
    finally:
        cursor.close()
        conn.close()

    # Tekil cari listesini sıralı bir listeye dönüştür
    cari_list_unique = sorted(list(cari_list_unique))

    return render_template('fatura_onay.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           faturalar=faturalar,
                           cari_list=cari_list,
                           cari_list_unique=cari_list_unique,
                           now=now,
                           is_admin=is_admin,
                           user_logoyetki=user_logoyetki)


@app.route('/fatura-onay/ekle', methods=['GET', 'POST'])
@login_required
@permission_required(menu_id=16, permission_type='add')
def fatura_onay_ekle():
    """Fatura onay ekleme sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    if request.method == 'POST':
        try:
            # Form verilerini al
            fatura_no = request.form.get('fatura_no')
            firma = request.form.get('firma')
            vade = request.form.get('vade', 0)
            not_metin = request.form.get('not', '')
            cari_ismi = request.form.get('cari_ismi', '')

            # Debug için form verilerini yazdır
            print(f"DEBUG - Form verileri: fatura_no={fatura_no}, firma={firma}, cari_ismi={cari_ismi}")

            # Girdi doğrulama
            if not fatura_no or not firma:
                flash('Fatura no ve firma alanları zorunludur.', 'error')
                return redirect(url_for('fatura_onay_ekle'))

            # Vade değerini integer'a çevir
            try:
                vade = int(vade)
            except ValueError:
                vade = 0

            conn = get_db_connection()
            cursor = conn.cursor()

            # Ana fatura kaydını oluştur
            cursor.execute("""
                INSERT INTO FaturaOnay (FaturaNo, Tarih, Firma, Vade, Notlar, OlusturanKullaniciID, CariIsmi)
                VALUES (?, GETDATE(), ?, ?, ?, ?, ?)
            """, (fatura_no, firma, vade, not_metin, user_id, cari_ismi))

            conn.commit()

            # Yeni eklenen kaydın ID'sini al
            cursor.execute("SELECT @@IDENTITY")
            fatura_id = cursor.fetchone()[0]

            # Dosya yüklemeleri için ayrı bir işlem başlat
            # Her dosya için ayrı bir işlem yapalım ki hata olursa diğerlerini etkilemesin
            files = request.files.getlist('dosyalar')
            for file in files:
                if file and file.filename:
                    try:
                        filename = secure_filename(file.filename)
                        file_ext = os.path.splitext(filename)[1].lower()

                        # İzin verilen dosya uzantılarını kontrol et
                        if file_ext in ['.png', '.jpg', '.jpeg', '.pdf', '.xlsx', '.xls']:
                            # Dosya içeriğini oku
                            file_content = file.read()

                            # Dosyayı veritabanına ekle
                            file_cursor = conn.cursor()
                            file_cursor.execute("""
                                INSERT INTO FaturaOnayDosyalari (FaturaID, DosyaAdi, DosyaUzantisi, DosyaIcerigi)
                                VALUES (?, ?, ?, ?)
                            """, (fatura_id, filename, file_ext, pyodbc.Binary(file_content)))

                            conn.commit()
                            file_cursor.close()
                        else:
                            flash(
                                f'{filename} dosyası izin verilen formatta değil. Sadece PNG, JPG, PDF ve Excel dosyaları yüklenebilir.',
                                'warning')
                    except Exception as file_error:
                        print(f"Dosya yükleme hatası ({filename}): {str(file_error)}")
                        flash(f"'{filename}' dosyası yüklenirken hata oluştu.", 'warning')
                        # Dosya hatası ana işlemi etkilemesin diye continue kullanıyoruz
                        continue

            # İşlemi logla
            log_user_action(user_id, 'FATURA_ONAY_EKLE', f'Fatura onay kaydı eklendi: {fatura_no}')

            flash('Fatura onay kaydı başarıyla eklendi.', 'success')
            return redirect(url_for('fatura_onay'))

        except Exception as e:
            print(f"Fatura ekleme hatası: {str(e)}")
            if 'conn' in locals() and conn:
                conn.rollback()
            flash(f'Fatura onay kaydı eklenirken bir hata oluştu: {str(e)}', 'error')
        finally:
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'conn' in locals() and conn:
                conn.close()

    return render_template('fatura_onay_detay.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           is_edit_mode=False)


# IMPORTANT: Replace the existing routes with these implementations!
@app.route('/fatura-onay/detay/<int:fatura_id>')
@login_required
@permission_required(menu_id=16, permission_type='view')
def fatura_onay_detay(fatura_id):
    """Fatura onay detay sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Check if user has permission to view this record
    is_admin = session.get('is_admin', False)
    user_logoyetki = 0

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get LogoYetki value for the current user
        cursor.execute("SELECT LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logoyetki = row[0] if row and row[0] is not None else 0

        # Get fatura details
        cursor.execute("""
            SELECT 
                f.FaturaID, 
                f.FaturaNo, 
                f.Tarih, 
                f.Firma, 
                f.Vade, 
                f.OlusturanKullaniciID,
                u.FullName as OlusturanKullaniciAd,
                u.Username as OlusturanKullanici,
                f.OdemeYapildi,
                CASE WHEN f.OdemeYapildi = 1 THEN 'Ödendi' ELSE 'Ödeme Bekliyor' END as OdemeDurumu,
                f.OdemeTarihi,
                f.OnaylayanKullaniciID,
                o.FullName as OnaylayanKullaniciAd,
                o.Username as OnaylayanKullanici,
                f.Notlar,
                f.CariIsmi
            FROM 
                FaturaOnay f
            JOIN 
                Users u ON f.OlusturanKullaniciID = u.UserID
            LEFT JOIN 
                Users o ON f.OnaylayanKullaniciID = o.UserID
            WHERE 
                f.FaturaID = ?
        """, (fatura_id,))

        row = cursor.fetchone()

        if not row:
            flash('Fatura bulunamadı.', 'error')
            return redirect(url_for('fatura_onay'))

        # Check permission
        olusturan_kullanici_id = row[5]
        if not (is_admin or user_logoyetki == 1 or olusturan_kullanici_id == user_id):
            flash('Bu faturayı görüntüleme yetkiniz bulunmamaktadır.', 'error')
            return redirect(url_for('fatura_onay'))

        # Format date
        tarih = row[2]
        formatted_tarih = tarih.strftime('%Y-%m-%d') if tarih and hasattr(tarih, 'strftime') else str(
            tarih) if tarih else ''

        # Format payment date if exists
        odeme_tarihi = row[10]
        formatted_odeme_tarihi = odeme_tarihi.strftime('%d.%m.%Y') if odeme_tarihi and hasattr(odeme_tarihi,
                                                                                               'strftime') else ''

        firma = row[3]  # Get firma value for cari list query
        cari_ismi = row[15] or ''  # Get the current cari_ismi value

        fatura = {
            'fatura_id': row[0],
            'fatura_no': row[1],
            'tarih': formatted_tarih,
            'firma': firma,
            'vade': row[4],
            'olusturan_kullanici_id': row[5],
            'olusturan_kullanici': row[6] or row[7],  # Use FullName if available, otherwise Username
            'odeme_yapildi': row[8],
            'odeme_durumu': row[9],
            'odeme_tarihi': formatted_odeme_tarihi,
            'onaylayan_kullanici_id': row[11],
            'onaylayan_kullanici': row[12] or row[13],  # Use FullName if available, otherwise Username
            'notlar': row[14],
            'cari_ismi': cari_ismi
        }

        # Get attached files
        cursor.execute("""
            SELECT DosyaID, DosyaAdi, DosyaUzantisi, YuklemeTarihi
            FROM FaturaOnayDosyalari
            WHERE FaturaID = ?
            ORDER BY YuklemeTarihi DESC
        """, (fatura_id,))

        dosyalar = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Format date
            yukleme_tarihi = row[3]
            formatted_yukleme_tarihi = yukleme_tarihi.strftime('%d.%m.%Y %H:%M') if yukleme_tarihi and hasattr(
                yukleme_tarihi, 'strftime') else str(yukleme_tarihi) if yukleme_tarihi else ''

            dosyalar.append({
                'dosya_id': row[0],
                'dosya_adi': row[1],
                'dosya_uzantisi': row[2],
                'yukleme_tarihi': formatted_yukleme_tarihi
            })

    except Exception as e:
        flash(f'Fatura detayları alınırken bir hata oluştu: {str(e)}', 'error')
        return redirect(url_for('fatura_onay'))
    finally:
        cursor.close()
        conn.close()

    return render_template('fatura_onay_detay.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           fatura=fatura,
                           dosyalar=dosyalar,
                           is_edit_mode=True,
                           can_approve=(is_admin or user_logoyetki == 1))


@app.route('/fatura-onay/edit/<int:fatura_id>', methods=['POST'])
@login_required
def fatura_onay_edit(fatura_id):
    """Fatura onay düzenleme."""
    user_id = session['user_id']

    # Check if user has permission to edit this record
    is_admin = session.get('is_admin', False)
    user_logoyetki = 0

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get LogoYetki value for the current user
        cursor.execute("SELECT LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logoyetki = row[0] if row and row[0] is not None else 0

        # Get current record owner
        cursor.execute("SELECT OlusturanKullaniciID, OdemeYapildi FROM FaturaOnay WHERE FaturaID = ?", (fatura_id,))
        row = cursor.fetchone()

        if not row:
            flash('Fatura bulunamadı.', 'error')
            return redirect(url_for('fatura_onay'))

        olusturan_kullanici_id = row[0]
        odeme_yapildi = row[1]

        # Check permission
        can_edit = (is_admin or user_logoyetki == 1 or olusturan_kullanici_id == user_id)
        if not can_edit:
            flash('Bu faturayı düzenleme yetkiniz bulunmamaktadır.', 'error')
            return redirect(url_for('fatura_onay'))

        # If payment is already made, only admin or logoyetki=1 users can edit
        if odeme_yapildi and not (is_admin or user_logoyetki == 1):
            flash('Ödemesi yapılmış fatura düzenlenemez.', 'error')
            return redirect(url_for('fatura_onay'))

        # Get form data
        fatura_no = request.form.get('fatura_no')
        firma = request.form.get('firma')
        vade = request.form.get('vade', 0)
        not_metin = request.form.get('not', '')
        cari_ismi = request.form.get('cari_ismi', '')

        print(f"DEBUG - Form verileri: fatura_no={fatura_no}, firma={firma}, cari_ismi={cari_ismi}")

        # Validate input
        if not fatura_no or not firma:
            flash('Fatura no ve firma alanları zorunludur.', 'error')
            return redirect(url_for('fatura_onay_detay', fatura_id=fatura_id))

        # Convert vade to integer
        try:
            vade = int(vade)
        except ValueError:
            vade = 0

        # Update record including CariIsmi
        cursor.execute("""
            UPDATE FaturaOnay
            SET FaturaNo = ?, Firma = ?, Vade = ?, Notlar = ?, CariIsmi = ?
            WHERE FaturaID = ?
        """, (fatura_no, firma, vade, not_metin, cari_ismi, fatura_id))

        conn.commit()

        # Handle file uploads - her dosya için ayrı işlem yapalım
        files = request.files.getlist('dosyalar')
        for file in files:
            if file and file.filename:
                try:
                    filename = secure_filename(file.filename)
                    file_ext = os.path.splitext(filename)[1].lower()

                    # Check if extension is allowed
                    if file_ext in ['.png', '.jpg', '.jpeg', '.pdf', '.xlsx', '.xls']:
                        # Dosya içeriğini oku
                        file_content = file.read()

                        # Yeni bir bağlantı ve cursor açalım
                        file_cursor = conn.cursor()
                        file_cursor.execute("""
                            INSERT INTO FaturaOnayDosyalari (FaturaID, DosyaAdi, DosyaUzantisi, DosyaIcerigi)
                            VALUES (?, ?, ?, ?)
                        """, (fatura_id, filename, file_ext, pyodbc.Binary(file_content)))

                        conn.commit()
                        file_cursor.close()
                    else:
                        flash(
                            f'{filename} dosyası izin verilen formatta değil. Sadece PNG, JPG, PDF ve Excel dosyaları yüklenebilir.',
                            'warning')
                except Exception as file_error:
                    print(f"Dosya yükleme hatası ({filename}): {str(file_error)}")
                    flash(f"'{filename}' dosyası yüklenirken hata oluştu.", 'warning')
                    # Hata durumunda bir sonraki dosyaya geç
                    continue

        # Log action
        log_user_action(user_id, 'FATURA_ONAY_DUZENLE', f'Fatura onay kaydı düzenlendi: ID={fatura_id}')

        flash('Fatura onay kaydı başarıyla güncellendi.', 'success')

    except Exception as e:
        conn.rollback()
        flash(f'Fatura onay kaydı güncellenirken bir hata oluştu: {str(e)}', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('fatura_onay_detay', fatura_id=fatura_id))


@app.route('/fatura-onay/delete/<int:fatura_id>', methods=['POST'])
@login_required
def fatura_onay_delete(fatura_id):
    """Fatura onay silme."""
    user_id = session['user_id']

    # Check if user has permission to delete this record
    is_admin = session.get('is_admin', False)
    user_logoyetki = 0

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get LogoYetki value for the current user
        cursor.execute("SELECT LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logoyetki = row[0] if row and row[0] is not None else 0

        # Get current record owner and details
        cursor.execute("""
            SELECT 
                FaturaID, OlusturanKullaniciID, FaturaNo, OdemeYapildi, Tarih, Firma, Vade, 
                Notlar, OdemeTarihi, OnaylayanKullaniciID, CariIsmi
            FROM FaturaOnay 
            WHERE FaturaID = ?
        """, (fatura_id,))

        row = cursor.fetchone()

        if not row:
            return jsonify({'success': False, 'message': 'Fatura bulunamadı.'})

        fatura_id_val = row[0]
        olusturan_kullanici_id = row[1]
        fatura_no = row[2]
        odeme_yapildi = row[3]
        tarih = row[4]
        firma = row[5]
        vade = row[6]
        notlar = row[7]
        odeme_tarihi = row[8]
        onaylayan_kullanici_id = row[9]
        cari_ismi = row[10]

        # Check permission
        can_delete = (is_admin or user_logoyetki == 1 or olusturan_kullanici_id == user_id)
        if not can_delete:
            return jsonify({'success': False, 'message': 'Bu faturayı silme yetkiniz bulunmamaktadır.'})

        # If payment is already made, NEVER allow delete (even for admins)
        if odeme_yapildi:
            return jsonify({'success': False, 'message': 'Ödemesi yapılmış fatura silinemez!'})

        # Before deleting, backup the record to DeletedFaturaOnay table
        delete_reason = "Kullanıcı tarafından silindi"

        # 1. Backup fatura record
        cursor.execute("""
            INSERT INTO DeletedFaturaOnay (
                FaturaID, FaturaNo, Tarih, Firma, Vade, Notlar, OlusturanKullaniciID, 
                OdemeYapildi, OdemeTarihi, OnaylayanKullaniciID, CariIsmi, DeletedByUserID, DeletedDate, DeleteReason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE(), ?)
        """, (
            fatura_id_val, fatura_no, tarih, firma, vade, notlar, olusturan_kullanici_id,
            odeme_yapildi, odeme_tarihi, onaylayan_kullanici_id, cari_ismi, user_id, delete_reason
        ))

        # 2. Get and backup all associated files
        cursor.execute("""
            SELECT DosyaID, DosyaAdi, DosyaUzantisi, YuklemeTarihi, DosyaIcerigi
            FROM FaturaOnayDosyalari
            WHERE FaturaID = ?
        """, (fatura_id,))

        dosyalar = cursor.fetchall()
        for dosya in dosyalar:
            dosya_id = dosya[0]
            dosya_adi = dosya[1]
            dosya_uzantisi = dosya[2]
            yukleme_tarihi = dosya[3]
            dosya_icerigi = dosya[4]

            # Insert each file into DeletedFaturaOnayDosyalari
            cursor.execute("""
                INSERT INTO DeletedFaturaOnayDosyalari (
                    OriginalDosyaID, FaturaID, DosyaAdi, DosyaUzantisi, 
                    YuklemeTarihi, DosyaIcerigi, DeletedByUserID, DeletedDate
                ) VALUES (?, ?, ?, ?, ?, ?, ?, GETDATE())
            """, (
                dosya_id, fatura_id, dosya_adi, dosya_uzantisi,
                yukleme_tarihi, dosya_icerigi, user_id
            ))

        # 3. Now delete the original files
        cursor.execute("DELETE FROM FaturaOnayDosyalari WHERE FaturaID = ?", (fatura_id,))

        # 4. Delete the original fatura record
        cursor.execute("DELETE FROM FaturaOnay WHERE FaturaID = ?", (fatura_id,))

        conn.commit()

        # Log action
        log_user_action(user_id, 'FATURA_ONAY_SIL', f'Fatura onay kaydı silindi: {fatura_no}')

        return jsonify({'success': True, 'message': 'Fatura onay kaydı başarıyla silindi.'})

    except Exception as e:
        conn.rollback()
        print(f"Fatura silme hatası: {str(e)}")
        return jsonify({'success': False, 'message': f'Fatura onay kaydı silinirken bir hata oluştu: {str(e)}'})
    finally:
        cursor.close()
        conn.close()


@app.route('/fatura-onay/approve/<int:fatura_id>', methods=['POST'])
@login_required
def fatura_onay_approve(fatura_id):
    """Fatura ödeme onay."""
    user_id = session['user_id']

    # Check if user has permission to approve payments
    is_admin = session.get('is_admin', False)
    user_logoyetki = 0

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get LogoYetki value for the current user
        cursor.execute("SELECT LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logoyetki = row[0] if row and row[0] is not None else 0

        # Check permission
        if not (is_admin or user_logoyetki == 1):
            return jsonify({'success': False, 'message': 'Ödeme onaylama yetkiniz bulunmamaktadır.'})

        # Get fatura details
        cursor.execute("SELECT FaturaNo, OdemeYapildi FROM FaturaOnay WHERE FaturaID = ?", (fatura_id,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'success': False, 'message': 'Fatura bulunamadı.'})

        fatura_no = row[0]
        odeme_yapildi = row[1]

        # Check if already approved
        if odeme_yapildi:
            return jsonify({'success': False, 'message': 'Bu fatura zaten ödenmiş.'})

        # Update payment status
        cursor.execute("""
            UPDATE FaturaOnay
            SET OdemeYapildi = 1, OdemeTarihi = GETDATE(), OnaylayanKullaniciID = ?
            WHERE FaturaID = ?
        """, (user_id, fatura_id))

        conn.commit()

        # Log action
        log_user_action(user_id, 'FATURA_ODEME_ONAY', f'Fatura ödemesi onaylandı: {fatura_no}')

        return jsonify({'success': True, 'message': 'Fatura ödemesi başarıyla onaylandı.'})

    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': f'Fatura ödemesi onaylanırken bir hata oluştu: {str(e)}'})
    finally:
        cursor.close()
        conn.close()


@app.route('/fatura-onay/dosya/<int:dosya_id>')
@login_required
def fatura_onay_dosya_indir(dosya_id):
    """Fatura dosyası indirme."""
    user_id = session['user_id']

    # Check if user has permission to download this file
    is_admin = session.get('is_admin', False)
    user_logoyetki = 0

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get LogoYetki value for the current user
        cursor.execute("SELECT LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logoyetki = row[0] if row and row[0] is not None else 0

        # Get file details and check permission - blob verilerini doğrudan sorgulama
        cursor.execute("""
            SELECT d.DosyaAdi, d.DosyaUzantisi, f.OlusturanKullaniciID
            FROM FaturaOnayDosyalari d
            JOIN FaturaOnay f ON d.FaturaID = f.FaturaID
            WHERE d.DosyaID = ?
        """, (dosya_id,))

        row = cursor.fetchone()

        if not row:
            flash('Dosya bulunamadı.', 'error')
            return redirect(url_for('fatura_onay'))

        dosya_adi = row[0]
        dosya_uzantisi = row[1]
        olusturan_kullanici_id = row[2]

        # Check permission
        can_download = (is_admin or user_logoyetki == 1 or olusturan_kullanici_id == user_id)
        if not can_download:
            flash('Bu dosyayı indirme yetkiniz bulunmamaktadır.', 'error')
            return redirect(url_for('fatura_onay'))

        # Dosya içeriğini ayrı bir sorgu ile al
        cursor.execute("""
            SELECT DosyaIcerigi
            FROM FaturaOnayDosyalari
            WHERE DosyaID = ?
        """, (dosya_id,))

        file_row = cursor.fetchone()
        if not file_row or not file_row[0]:
            flash('Dosya içeriği bulunamadı.', 'error')
            return redirect(url_for('fatura_onay'))

        dosya_icerigi = file_row[0]

        # Log action
        log_user_action(user_id, 'FATURA_DOSYA_INDIR', f'Fatura dosyası indirildi: {dosya_adi}')

        cursor.close()
        conn.close()

        # Set the appropriate Content-Type
        if dosya_uzantisi == '.pdf':
            mimetype = 'application/pdf'
        elif dosya_uzantisi in ['.xlsx', '.xls']:
            mimetype = 'application/vnd.ms-excel'
        elif dosya_uzantisi == '.png':
            mimetype = 'image/png'
        elif dosya_uzantisi in ['.jpg', '.jpeg']:
            mimetype = 'image/jpeg'
        else:
            mimetype = 'application/octet-stream'

        # Return the file
        from flask import send_file
        from io import BytesIO
        return send_file(
            BytesIO(dosya_icerigi),
            mimetype=mimetype,
            as_attachment=True,
            download_name=dosya_adi
        )

    except Exception as e:
        print(f"Dosya indirme hatası: {str(e)}")
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()
        flash(f'Dosya indirilirken bir hata oluştu: {str(e)}', 'error')
        return redirect(url_for('fatura_onay'))


@app.route('/fatura-onay/dosya/delete/<int:dosya_id>', methods=['POST'])
@login_required
def fatura_onay_dosya_delete(dosya_id):
    """Fatura dosyası silme."""
    user_id = user_id = session['user_id']

    # Check if user has permission to delete this file
    is_admin = session.get('is_admin', False)
    user_logoyetki = 0

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get LogoYetki value for the current user
        cursor.execute("SELECT LogoYetki FROM Users WHERE UserID = ?", (user_id,))
        row = cursor.fetchone()
        user_logoyetki = row[0] if row and row[0] is not None else 0

        # Get file details and check permission
        cursor.execute("""
            SELECT d.DosyaAdi, f.FaturaID, f.OlusturanKullaniciID, f.OdemeYapildi
            FROM FaturaOnayDosyalari d
            JOIN FaturaOnay f ON d.FaturaID = f.FaturaID
            WHERE d.DosyaID = ?
        """, (dosya_id,))

        row = cursor.fetchone()

        if not row:
            return jsonify({'success': False, 'message': 'Dosya bulunamadı.'})

        dosya_adi = row[0]
        fatura_id = row[1]
        olusturan_kullanici_id = row[2]
        odeme_yapildi = row[3]

        # Check permission
        can_delete = (is_admin or user_logoyetki == 1 or olusturan_kullanici_id == user_id)
        if not can_delete:
            return jsonify({'success': False, 'message': 'Bu dosyayı silme yetkiniz bulunmamaktadır.'})

        # If payment is already made, only admin or logoyetki=1 users can delete
        if odeme_yapildi and not (is_admin or user_logoyetki == 1):
            return jsonify({'success': False, 'message': 'Ödemesi yapılmış faturanın dosyası silinemez.'})

        # Delete file
        cursor.execute("DELETE FROM FaturaOnayDosyalari WHERE DosyaID = ?", (dosya_id,))
        conn.commit()

        # Log action
        log_user_action(user_id, 'FATURA_DOSYA_SIL', f'Fatura dosyası silindi: {dosya_adi}')

        return jsonify({'success': True, 'message': 'Fatura dosyası başarıyla silindi.', 'fatura_id': fatura_id})

    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': f'Dosya silinirken bir hata oluştu: {str(e)}'})
    finally:
        cursor.close()
        conn.close()


@app.route('/get-cari-list', methods=['GET'])
@login_required
def get_cari_list():
    """Get combined cari list from TIGERDB for dropdown selection."""
    try:
        search_term = request.args.get('term', '')  # 'term' Select2 tarafından gönderilen parametre adı
        print(f"DEBUG - Cari search term: {search_term}")

        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()

        # Arama terimi varsa filtrele, yoksa tüm sonuçları getir (limit ile)
        if search_term:
            search_pattern = f"%{search_term}%"
            cursor.execute("""
                SELECT TOP 100 DEFINITION_
                FROM (
                    SELECT DEFINITION_
                    FROM LG_225_CLCARD
                    WHERE DEFINITION_ LIKE ?
                    UNION ALL 
                    SELECT DEFINITION_
                    FROM LG_425_CLCARD
                    WHERE DEFINITION_ LIKE ?
                ) AS CombinedResults
                ORDER BY DEFINITION_ ASC
            """, (search_pattern, search_pattern))
        else:
            cursor.execute("""
                SELECT TOP 100 DEFINITION_
                FROM (
                    SELECT DEFINITION_
                    FROM LG_225_CLCARD
                    UNION ALL 
                    SELECT DEFINITION_
                    FROM LG_425_CLCARD
                ) AS CombinedResults
                ORDER BY DEFINITION_ ASC
            """)

        # Select2 formatında sonuçları hazırla
        results = []
        while True:
            row = cursor.fetchone()
            if not row:
                break
            results.append({
                "id": row[0],  # Cari ismini hem id hem text olarak kullan
                "text": row[0]
            })

        cursor.close()
        conn.close()

        print(f"DEBUG - Cari results count: {len(results)}")

        # Select2'nin beklediği formatta yanıt dön
        return jsonify({"results": results})

    except Exception as e:
        print(f"Cari listesi alınırken hata: {e}")
        return jsonify({"results": []})  # Hata durumunda boş sonuç dön


@app.route('/admin/silinen-faturalar')
@login_required
@admin_required
def admin_silinen_faturalar():
    """Silinen faturaları görüntüleme sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get deleted invoices
        cursor.execute("""
            SELECT 
                df.DeletedID,
                df.FaturaID,
                df.FaturaNo,
                df.Tarih,
                df.Firma,
                df.CariIsmi,
                df.OdemeYapildi,
                u1.FullName as OlusturanKullanici,
                u2.FullName as SilenKullanici,
                df.DeletedDate,
                df.DeleteReason
            FROM 
                DeletedFaturaOnay df
            LEFT JOIN 
                Users u1 ON df.OlusturanKullaniciID = u1.UserID
            LEFT JOIN 
                Users u2 ON df.DeletedByUserID = u2.UserID
            ORDER BY 
                df.DeletedDate DESC
        """)

        deleted_invoices = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Format dates
            tarih = row[3]
            silme_tarihi = row[9]

            formatted_tarih = tarih.strftime('%d.%m.%Y') if tarih and hasattr(tarih, 'strftime') else str(
                tarih) if tarih else ''
            formatted_silme_tarihi = silme_tarihi.strftime('%d.%m.%Y %H:%M') if silme_tarihi and hasattr(silme_tarihi,
                                                                                                         'strftime') else str(
                silme_tarihi) if silme_tarihi else ''

            deleted_invoices.append({
                'deleted_id': row[0],
                'fatura_id': row[1],
                'fatura_no': row[2],
                'tarih': formatted_tarih,
                'firma': row[4],
                'cari_ismi': row[5] or '',
                'odeme_yapildi': row[6],
                'olusturan_kullanici': row[7] or 'Bilinmiyor',
                'silen_kullanici': row[8] or 'Bilinmiyor',
                'silme_tarihi': formatted_silme_tarihi,
                'silme_nedeni': row[10] or ''
            })

    except Exception as e:
        flash(f'Silinen fatura verileri alınırken bir hata oluştu: {str(e)}', 'error')
        deleted_invoices = []
    finally:
        cursor.close()
        conn.close()

    return render_template('admin/silinen_faturalar.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           deleted_invoices=deleted_invoices)


# Route for viewing weekly meal menus
@app.route('/haftalik-yemek')
@login_required
def haftalik_yemek():
    """Haftalık yemek menüsü sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    # Get all menu records
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT 
                m.MenuID, 
                m.IlkTarih, 
                m.SonTarih, 
                m.Aciklama, 
                m.DosyaAdi,
                m.OlusturanKullaniciID,
                u.FullName as OlusturanKullaniciAd
            FROM 
                HaftalikYemekMenu m
            JOIN 
                Users u ON m.OlusturanKullaniciID = u.UserID
            ORDER BY 
                m.IlkTarih DESC
        """)

        menu_list = []
        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Format dates
            ilk_tarih = row[1]
            son_tarih = row[2]

            formatted_ilk_tarih = ilk_tarih.strftime('%d.%m.%Y') if ilk_tarih and hasattr(ilk_tarih,
                                                                                          'strftime') else str(
                ilk_tarih) if ilk_tarih else ''
            formatted_son_tarih = son_tarih.strftime('%d.%m.%Y') if son_tarih and hasattr(son_tarih,
                                                                                          'strftime') else str(
                son_tarih) if son_tarih else ''

            menu_list.append({
                'menu_id': row[0],
                'ilk_tarih': formatted_ilk_tarih,
                'son_tarih': formatted_son_tarih,
                'aciklama': row[3],
                'dosya_adi': row[4],
                'olusturan_kullanici_id': row[5],
                'olusturan_kullanici': row[6]
            })

    except Exception as e:
        flash(f'Yemek menüsü verileri alınırken bir hata oluştu: {str(e)}', 'error')
        menu_list = []
    finally:
        cursor.close()
        conn.close()

    # Check if user has permission to add new menu
    is_admin = session.get('is_admin', False)
    has_permission = False

    if is_admin:
        has_permission = True
    else:
        # Check if user has "İnsan Kaynakları" role
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT COUNT(*) 
                FROM UserRoles ur 
                JOIN Roles r ON ur.RoleID = r.RoleID 
                WHERE ur.UserID = ? AND r.RoleName = 'İnsan Kaynakları'
            """, (user_id,))

            count = cursor.fetchone()[0]
            has_permission = (count > 0)
        except Exception as e:
            print(f"Yetki kontrolü sırasında hata: {str(e)}")
        finally:
            cursor.close()
            conn.close()

    return render_template('haftalik_yemek.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           menu_list=menu_list,
                           now=now,
                           is_admin=is_admin,
                           has_permission=has_permission)


# Route for adding new menu
@app.route('/haftalik-yemek/ekle', methods=['GET', 'POST'])
@login_required
def haftalik_yemek_ekle():
    """Haftalık yemek menüsü ekleme sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Check if user has permission to add new menu
    is_admin = session.get('is_admin', False)
    has_permission = False

    if is_admin:
        has_permission = True
    else:
        # Check if user has "İnsan Kaynakları" role
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT COUNT(*) 
                FROM UserRoles ur 
                JOIN Roles r ON ur.RoleID = r.RoleID 
                WHERE ur.UserID = ? AND r.RoleName = 'İnsan Kaynakları'
            """, (user_id,))

            count = cursor.fetchone()[0]
            has_permission = (count > 0)
        except Exception as e:
            print(f"Yetki kontrolü sırasında hata: {str(e)}")
        finally:
            cursor.close()
            conn.close()

    if not has_permission:
        flash('Bu sayfaya erişim yetkiniz bulunmamaktadır.', 'error')
        return redirect(url_for('haftalik_yemek'))

    if request.method == 'POST':
        try:
            # Get form data
            ilk_tarih = request.form.get('ilk_tarih')
            son_tarih = request.form.get('son_tarih')
            aciklama = request.form.get('aciklama')

            # Validate dates
            try:
                ilk_tarih_obj = datetime.strptime(ilk_tarih, '%Y-%m-%d')
                son_tarih_obj = datetime.strptime(son_tarih, '%Y-%m-%d')

                # Check if date range is valid
                if son_tarih_obj < ilk_tarih_obj:
                    flash('Son tarih, ilk tarihten önce olamaz.', 'error')
                    return redirect(url_for('haftalik_yemek_ekle'))

                # Check if date range is not more than 6 days
                if (son_tarih_obj - ilk_tarih_obj).days > 6:
                    flash('Tarih aralığı 6 günden fazla olamaz.', 'error')
                    return redirect(url_for('haftalik_yemek_ekle'))

            except ValueError:
                flash('Geçersiz tarih formatı.', 'error')
                return redirect(url_for('haftalik_yemek_ekle'))

            # Process file upload
            file = request.files.get('dosya')
            if file and file.filename:
                filename = secure_filename(file.filename)
                file_ext = os.path.splitext(filename)[1].lower()

                # Check if extension is allowed
                if file_ext not in ['.png', '.jpg', '.jpeg']:
                    flash('Sadece PNG, JPG ve JPEG formatları desteklenmektedir.', 'error')
                    return redirect(url_for('haftalik_yemek_ekle'))

                # Read file content
                file_content = file.read()

                # Insert into database
                conn = get_db_connection()
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO HaftalikYemekMenu 
                    (IlkTarih, SonTarih, Aciklama, DosyaAdi, DosyaUzantisi, 
                     DosyaIcerigi, OlusturanKullaniciID, OlusturmaTarihi)
                    VALUES (?, ?, ?, ?, ?, ?, ?, GETDATE())
                """, (
                    ilk_tarih,
                    son_tarih,
                    aciklama,
                    filename,
                    file_ext,
                    pyodbc.Binary(file_content),
                    user_id
                ))

                conn.commit()

                # Log action
                log_user_action(user_id, 'HAFTALIK_YEMEK_EKLE',
                                f'Haftalık yemek menüsü eklendi: {ilk_tarih} - {son_tarih}')

                flash('Haftalık yemek menüsü başarıyla eklendi.', 'success')
                return redirect(url_for('haftalik_yemek'))

            else:
                flash('Lütfen bir menü görseli seçin.', 'error')
                return redirect(url_for('haftalik_yemek_ekle'))

        except Exception as e:
            flash(f'Menü eklenirken bir hata oluştu: {str(e)}', 'error')
            return redirect(url_for('haftalik_yemek_ekle'))

    return render_template('haftalik_yemek_ekle.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions)


# Route for viewing menu image (continued)
@app.route('/haftalik-yemek/goruntu/<int:menu_id>')
@login_required
def haftalik_yemek_goruntu(menu_id):
    """Haftalık yemek menüsü görüntüsünü görüntüleme."""

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT DosyaIcerigi, DosyaAdi, DosyaUzantisi
            FROM HaftalikYemekMenu
            WHERE MenuID = ?
        """, (menu_id,))

        row = cursor.fetchone()

        if not row or not row[0]:
            cursor.close()
            conn.close()
            flash('Menü görüntüsü bulunamadı.', 'error')
            return redirect(url_for('haftalik_yemek'))

        dosya_icerigi = row[0]
        dosya_adi = row[1]
        dosya_uzantisi = row[2]

        # Log action
        log_user_action(session['user_id'], 'HAFTALIK_YEMEK_GORUNTU',
                        f'Haftalık yemek menüsü görüntülendi: {dosya_adi}')

        cursor.close()
        conn.close()

        # Set the appropriate Content-Type
        if dosya_uzantisi == '.png':
            mimetype = 'image/png'
        elif dosya_uzantisi in ['.jpg', '.jpeg']:
            mimetype = 'image/jpeg'
        else:
            mimetype = 'application/octet-stream'

        # Return the file
        return send_file(
            BytesIO(dosya_icerigi),
            mimetype=mimetype,
            as_attachment=False,
            download_name=dosya_adi
        )

    except Exception as e:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

        flash(f'Görüntü yüklenirken bir hata oluştu: {str(e)}', 'error')
        return redirect(url_for('haftalik_yemek'))


@app.route('/haftalik-yemek/sil/<int:menu_id>', methods=['POST'])
@login_required
def haftalik_yemek_sil(menu_id):
    """Haftalık yemek menüsünü silme."""
    user_id = session['user_id']

    # Check permissions
    is_admin = session.get('is_admin', False)
    has_permission = False

    if is_admin:
        has_permission = True
    else:
        # Check if user has "İnsan Kaynakları" role
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                    SELECT COUNT(*) 
                    FROM UserRoles ur 
                    JOIN Roles r ON ur.RoleID = r.RoleID 
                    WHERE ur.UserID = ? AND r.RoleName = 'İnsan Kaynakları'
                """, (user_id,))

            count = cursor.fetchone()[0]
            has_permission = (count > 0)
        except Exception as e:
            print(f"Yetki kontrolü sırasında hata: {str(e)}")
        finally:
            cursor.close()
            conn.close()

    if not has_permission:
        flash('Bu menüyü silme yetkiniz bulunmamaktadır.', 'error')
        return redirect(url_for('haftalik_yemek'))

    # Get menu details for logging before deletion
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # First, get menu details for logging
        cursor.execute("""
                SELECT IlkTarih, SonTarih, DosyaAdi 
                FROM HaftalikYemekMenu 
                WHERE MenuID = ?
            """, (menu_id,))

        row = cursor.fetchone()

        if not row:
            flash('Silinecek menü bulunamadı.', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('haftalik_yemek'))

        ilk_tarih = row[0]
        son_tarih = row[1]
        dosya_adi = row[2]

        # Format dates for logging
        formatted_ilk_tarih = ilk_tarih.strftime('%d.%m.%Y') if ilk_tarih and hasattr(ilk_tarih,
                                                                                      'strftime') else str(
            ilk_tarih)
        formatted_son_tarih = son_tarih.strftime('%d.%m.%Y') if son_tarih and hasattr(son_tarih,
                                                                                      'strftime') else str(
            son_tarih)

        # Delete the menu
        cursor.execute("DELETE FROM HaftalikYemekMenu WHERE MenuID = ?", (menu_id,))
        conn.commit()

        # Log the action
        log_user_action(user_id, 'HAFTALIK_YEMEK_SIL',
                        f'Haftalık yemek menüsü silindi: {formatted_ilk_tarih} - {formatted_son_tarih}, {dosya_adi}')

        flash('Menü başarıyla silindi.', 'success')

    except Exception as e:
        conn.rollback()
        flash(f'Menü silinirken bir hata oluştu: {str(e)}', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('haftalik_yemek'))


@app.route('/gunluk-satis-raporu')
@login_required
@permission_required(menu_id=17, permission_type='view')  # Menü ID'sini uygun şekilde ayarlayın
def gunluk_satis_raporu():
    """Günlük satış raporu sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    # Get sales data from TIGERDB
    conn = get_db_connection2()  # TIGERDB bağlantısı
    cursor = conn.cursor()
    satis_data = []

    try:
        cursor.execute("""
            SELECT TOP (1000) 
                [CARI],
                [SATIŞ ELEMANI],
                [Malzeme Grup Kodu],
                [MALZEME ADI],
                [BRÜT_KG],
                [NET_KG],
                [FİRE KG],
                [HURDA],
                [BIRIM FIYAT],
                [FIYAT],
                [TUTAR],
                [DOVIZ_TOPLAM],
                [Döviz Türü],
                [VADE],
                [TESLİM TARİHİ],
                [İRSALİYE TARİHİ],
                [TESLİM DURUM]
            FROM [TIGERDB].[dbo].[BYT_SATIS_RAPORU_GUNLUK_YDC]
            ORDER BY [CARI], [Malzeme Grup Kodu], [MALZEME ADI]
        """)

        while True:
            row = cursor.fetchone()
            if not row:
                break

            # Tarihleri formatlayalım
            teslim_tarihi = row[14]
            irsaliye_tarihi = row[15]

            formatted_teslim_tarihi = teslim_tarihi.strftime('%d.%m.%Y') if teslim_tarihi and hasattr(teslim_tarihi,
                                                                                                      'strftime') else str(
                teslim_tarihi) if teslim_tarihi else ''
            formatted_irsaliye_tarihi = irsaliye_tarihi.strftime('%d.%m.%Y') if irsaliye_tarihi and hasattr(
                irsaliye_tarihi, 'strftime') else str(irsaliye_tarihi) if irsaliye_tarihi else ''

            satis_data.append({
                'cari': row[0] or '',
                'satis_elemani': row[1] or '',
                'malzeme_grup_kodu': row[2] or '',
                'malzeme_adi': row[3] or '',
                'brut_kg': float(row[4]) if row[4] is not None else 0,
                'net_kg': float(row[5]) if row[5] is not None else 0,
                'fire_kg': float(row[6]) if row[6] is not None else 0,
                'hurda': float(row[7]) if row[7] is not None else 0,
                'birim_fiyat': float(row[8]) if row[8] is not None else 0,
                'fiyat': float(row[9]) if row[9] is not None else 0,
                'tutar': float(row[10]) if row[10] is not None else 0,
                'doviz_toplam': float(row[11]) if row[11] is not None else 0,
                'doviz_turu': row[12] or 'TL',
                'vade': row[13] or '',
                'teslim_tarihi': formatted_teslim_tarihi,
                'irsaliye_tarihi': formatted_irsaliye_tarihi,
                'teslim_durum': row[16] or ''
            })

        # Verileri cari bazında grupla
        grouped_data = {}
        for item in satis_data:
            cari = item['cari']
            if cari not in grouped_data:
                grouped_data[cari] = {
                    'cari': cari,
                    'details': [],  # items yerine details kullanıyoruz
                    'total_brut_kg': 0,
                    'total_net_kg': 0,
                    'total_fire_kg': 0,
                    'total_hurda': 0,
                    'total_tutar': 0,
                    'total_doviz_toplam': 0
                }

            grouped_data[cari]['details'].append(item)  # items yerine details
            grouped_data[cari]['total_brut_kg'] += item['brut_kg']
            grouped_data[cari]['total_net_kg'] += item['net_kg']
            grouped_data[cari]['total_fire_kg'] += item['fire_kg']
            grouped_data[cari]['total_hurda'] += item['hurda']
            grouped_data[cari]['total_tutar'] += item['tutar']
            grouped_data[cari]['total_doviz_toplam'] += item['doviz_toplam']

        # Gruplandırılmış veriyi listeye çevir
        grouped_list = list(grouped_data.values())

    except Exception as e:
        flash(f'Satış raporu verileri alınırken hata oluştu: {str(e)}', 'error')
        grouped_list = []
    finally:
        cursor.close()
        conn.close()

    # İşlemi logla
    log_user_action(user_id, 'GUNLUK_SATIS_RAPORU_GORUNTULE', 'Günlük satış raporu görüntülendi')

    return render_template('gunluksatisraporu.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           grouped_data=grouped_list,
                           now=now)


# Add this route for daily sales details
@app.route('/ydc-satis-raporu/daily-details/<date>')
@login_required
def ydc_daily_sales_details(date):
    """Günlük satış detaylarını getir."""
    try:
        conn = get_db_connection2()
        cursor = conn.cursor()

        # Get detailed records for the specific date
        cursor.execute("""
            SELECT 
                SIPARIS_NO,
                CONVERT(varchar, TARIH, 108) as Saat,
                CARI,
                URUN_HIZMET_AD,
                CAST(NET_KG as FLOAT) as NET_KG,
                CAST(BRÜT_KG as FLOAT) as BRUT_KG,
                CASE WHEN ISNUMERIC([BIRIM FIYAT]) = 1 THEN CAST([BIRIM FIYAT] as FLOAT) ELSE 0 END as BIRIM_FIYAT,
                CAST(TUTAR as FLOAT) as TUTAR,
                CASE WHEN ISNUMERIC(VADE) = 1 THEN CAST(VADE as INT) ELSE 0 END as VADE,
                [ÖDEME TİPİ],
                [Sipariş Durumu],
                [SATIŞ ELEMANI],
                [TESLİM DURUM],
                [Faturalanma Durumu],
                [Fatura No]
            FROM ANT_TBL_BYT_SATIS_RAPORU_YDC
            WHERE [TAKIM İŞ EMRİ] = ''
            AND CONVERT(date, TARIH) = ?
            ORDER BY TARIH DESC
        """, (date,))

        records = []
        total_daily_sales = 0
        total_daily_kg = 0
        total_daily_orders = 0

        while True:
            row = cursor.fetchone()
            if not row:
                break

            tutar = float(row[7]) if row[7] else 0
            net_kg = float(row[4]) if row[4] else 0

            total_daily_sales += tutar
            total_daily_kg += net_kg
            total_daily_orders += 1

            records.append({
                'siparis_no': row[0],
                'saat': row[1],
                'cari': row[2],
                'urun': row[3],
                'net_kg': net_kg,
                'brut_kg': float(row[5]) if row[5] else 0,
                'birim_fiyat': float(row[6]) if row[6] else 0,
                'tutar': tutar,
                'vade': int(row[8]) if row[8] else 0,
                'odeme_tipi': row[9],
                'durum': row[10],
                'satis_elemani': row[11],
                'teslim_durum': row[12],
                'fatura_durum': row[13],
                'fatura_no': row[14]
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'records': records,
            'total_sales': total_daily_sales,
            'total_kg': total_daily_kg,
            'total_orders': total_daily_orders,
            'date': date
        })

    except Exception as e:
        print(f"Günlük detay alınırken hata: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })


@app.route('/mikroskop-yanlis-veri')
@login_required
@permission_required(menu_id=20, permission_type='view')  # Menü ID'nizi uygun şekilde ayarlayın
def mikroskop_yanlis_veri():
    """Mikroskop Yanlış Veri Kontrolü sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    # Get current date for display
    now = datetime.now()

    # Verileri SQL Server'dan çek
    conn = get_db_connection2()  # TIGERDB bağlantısı
    cursor = conn.cursor()

    try:
        query = """
            SELECT TOP 1000 
                [grpd_KayNo] AS [ID],
                [grpd_grup_no] AS [IS_EMRI],
                DEFINITION_ AS [CARI_ADI],
                [grpd_PARCAKODU] AS [PARCA_KODU],
                [grpd_PARCAADI] AS [PARCA_ADI],
                [grpd_PARCAMIKTAR] AS [ADET],
                [grpd_GENELTOPLAMKG] AS [BRUT_KG],
                [grpd_TOPLAMKGFIRE] AS [FIRE_KG],
                [grpd_TOPLAMKG] AS [NET_KG]
            FROM [TIGERDB].[dbo].[MS_ISEMRI_GRUPLAMA_D]
            LEFT OUTER JOIN LG_225_CLCARD ON CODE=grpd_CARIFIRMA
            WHERE grpd_grup_no LIKE 'YDC%'
            ORDER BY grpd_KayNo DESC
        """

        cursor.execute(query)

        # Verileri işlenebilir formata dönüştür
        columns = [column[0] for column in cursor.description]
        rows = []
        yanlis_veri_sayisi = 0  # Net > Brüt veya ikisi de 0 olan kayıt sayısı

        for row in cursor.fetchall():
            data = dict(zip(columns, row))

            # Sayısal verilerin tam olduğundan emin olalım
            data['BRUT_KG'] = float(data['BRUT_KG']) if data['BRUT_KG'] is not None else 0
            data['NET_KG'] = float(data['NET_KG']) if data['NET_KG'] is not None else 0
            data['FIRE_KG'] = float(data['FIRE_KG']) if data['FIRE_KG'] is not None else 0
            data['ADET'] = int(data['ADET']) if data['ADET'] is not None else 0

            # Hatalı veri kontrolü
            data['HATALI'] = (data['NET_KG'] > data['BRUT_KG'] or
                              data['NET_KG'] == 0 or
                              data['BRUT_KG'] == 0)

            if data['HATALI']:
                yanlis_veri_sayisi += 1

            rows.append(data)

    except Exception as e:
        flash(f'Veriler alınırken bir hata oluştu: {str(e)}', 'error')
        rows = []
        yanlis_veri_sayisi = 0
    finally:
        cursor.close()
        conn.close()

    return render_template('mikroskop_yanlis_veri.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           rows=rows,
                           yanlis_veri_sayisi=yanlis_veri_sayisi,
                           now=now)


@app.route('/mikroskop-yanlis-veri/guncelle', methods=['POST'])
@login_required
@permission_required(menu_id=20, permission_type='edit')
def mikroskop_yanlis_veri_guncelle():
    """Üretim verisini güncelle."""
    try:
        # Form verilerini al
        id = request.form.get('id')
        brut_kg = request.form.get('brut_kg')
        net_kg = request.form.get('net_kg')
        fire_kg = request.form.get('fire_kg')

        # Veri doğrulama
        if not id or not brut_kg or not net_kg:
            return jsonify({'success': False, 'message': 'ID, Brüt KG ve Net KG alanları zorunludur.'})

        # Sayısal değerlere dönüştür
        try:
            brut_kg = float(brut_kg)
            net_kg = float(net_kg)
            fire_kg = float(fire_kg) if fire_kg else 0
        except ValueError:
            return jsonify({'success': False, 'message': 'Geçersiz sayısal değer.'})

        # Mantıksal kontrol
        if net_kg > brut_kg:
            return jsonify({'success': False, 'message': 'Net KG, Brüt KG\'dan büyük olamaz.'})

        # Veritabanında güncelleme yap
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()

        try:
            update_query = """
                UPDATE MS_ISEMRI_GRUPLAMA_D
                SET 
                    grpd_GENELTOPLAMKG = ?,
                    grpd_TOPLAMKG = ?,
                    grpd_TOPLAMKGFIRE = ?
                WHERE grpd_KayNo = ?
            """

            cursor.execute(update_query, (brut_kg, net_kg, fire_kg, id))
            conn.commit()

            # Log action
            log_user_action(session['user_id'], 'MIKROSKOP_YANLIS_VERI_GUNCELLE', f'Üretim verisi güncellendi: ID={id}')

            return jsonify({'success': True, 'message': 'Veri başarıyla güncellendi.'})

        except Exception as e:
            return jsonify({'success': False, 'message': f'Güncelleme sırasında bir hata oluştu: {str(e)}'})
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'message': f'İşlem sırasında bir hata oluştu: {str(e)}'})


# Yeni route'ları ekleyin:

@app.route('/petrol-barkopos-guncelleme')
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def petrol_barkopos_guncelleme():
    """Petrol Barkopos Güncelleme sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    return render_template('petrol_barkopos_guncelleme.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions)


@app.route('/petrol-barkopos-guncelleme/z-rapor-data')
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def z_rapor_data():
    """Z Rapor verilerini getir."""
    try:
        tarih_filtre = request.args.get('tarih_filtre', '')
        evrak_id_filtre = request.args.get('evrak_id_filtre', '')

        conn = get_db_connection4()
        cursor = conn.cursor()

        # Base query
        query = """
            SELECT 
                Tarih,
                Evrak_Id,
                StokKodu,
                URN.UrunAdi,
                Evrak_Miktar,
                Kdv_Oran,
                Ana_Fiyat
            FROM URUN_HAREKETLERI HAR
            LEFT OUTER JOIN URUNLER URN ON URN.StokKod = HAR.StokKodu
            LEFT OUTER JOIN EVRAKLAR E ON E.Id = HAR.Evrak_Id 
            WHERE Karsilanan_Miktar = 1 AND E.Evrak_Tipi = 11
            AND Tarih >= '2025-05-01'
        """

        params = []

        # Add filters
        if tarih_filtre:
            query += " AND CAST(Tarih AS DATE) = ?"
            params.append(tarih_filtre)

        if evrak_id_filtre:
            query += " AND Evrak_Id = ?"
            params.append(evrak_id_filtre)

        query += " ORDER BY Tarih DESC"

        cursor.execute(query, params)

        data = []
        while True:
            row = cursor.fetchone()
            if not row:
                break
            data.append({
                'tarih': row[0].strftime('%d.%m.%Y') if row[0] else '',
                'evrak_id': row[1],
                'stok_kodu': row[2],
                'stok_adi': row[3] or '',
                'miktar': float(row[4]) if row[4] else 0,
                'kdv': float(row[5]) if row[5] else 0,
                'fiyat': float(row[6]) if row[6] else 0
            })

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'data': data})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/petrol-barkopos-guncelleme/giris-irsaliye-data')
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def giris_irsaliye_data():
    """Giriş İrsaliyesi verilerini getir."""
    try:
        tarih_filtre = request.args.get('tarih_filtre', '')
        cari_filtre = request.args.get('cari_filtre', '')
        evrak_id_filtre = request.args.get('evrak_id_filtre', '')

        conn = get_db_connection4()
        cursor = conn.cursor()

        # Base query
        query = """
            SELECT 
                HAR.Tarih,
                HAR.Evrak_Id,
                CARI.Unvan,
                HAR.StokKodu,                URN.UrunAdi,
                HAR.Evrak_Miktar,
                HAR.Kdv_Oran,
                HAR.Orj_Maliyet
            FROM URUN_HAREKETLERI HAR
            LEFT OUTER JOIN URUNLER URN ON URN.StokKod = HAR.StokKodu
            LEFT OUTER JOIN CARI_HESAP_HAREKETLERI CHA ON CHA.Evrak_Id = HAR.Evrak_Id
            LEFT OUTER JOIN CARILER CARI ON CARI.Id=CHA.Cari_Id
            WHERE Fifo_Maliyet = 1 AND CARI.Unvan IS NOT NULL
            AND HAR.Tarih >= '2025-05-01'
        """

        params = []

        # Add filters
        if tarih_filtre:
            query += " AND CAST(HAR.Tarih AS DATE) = ?"
            params.append(tarih_filtre)

        if cari_filtre:
            query += " AND CARI.Unvan LIKE ?"
            params.append(f'%{cari_filtre}%')

        if evrak_id_filtre:
            query += " AND HAR.Evrak_Id = ?"
            params.append(evrak_id_filtre)

        query += " ORDER BY HAR.Tarih DESC"

        cursor.execute(query, params)

        data = []
        while True:
            row = cursor.fetchone()
            if not row:
                break
            data.append({
                'tarih': row[0].strftime('%d.%m.%Y') if row[0] else '',
                'evrak_id': row[1],
                'cari': row[2] or '',
                'stok_kodu': row[3],
                'stok_adi': row[4] or '',
                'miktar': float(row[5]) if row[5] else 0,
                'kdv': float(row[6]) if row[6] else 0,
                'fiyat': float(row[7]) if row[7] else 0
            })

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'data': data})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/petrol-barkopos-guncelleme/z-rapor-update', methods=['POST'])
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def z_rapor_update():
    """Z Rapor güncelleme."""
    try:
        evrak_id = request.json.get('evrak_id')

        if not evrak_id:
            return jsonify({'success': False, 'message': 'Evrak ID gereklidir.'})

        conn = get_db_connection4()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE URUN_HAREKETLERI 
            SET Karsilanan_Miktar = 0 
            WHERE Karsilanan_Miktar = 1 AND Evrak_Id = ?
        """, (evrak_id,))

        affected_rows = cursor.rowcount
        conn.commit()

        # Log action
        log_user_action(session['user_id'], 'Z_RAPOR_GUNCELLE', f'Z Rapor güncellendi: Evrak ID={evrak_id}')

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'{affected_rows} kayıt güncellendi.',
            'affected_rows': affected_rows
        })

    except Exception as e:
        return jsonify({'success': False, 'message': f'Güncelleme sırasında hata: {str(e)}'})


@app.route('/petrol-barkopos-guncelleme/giris-irsaliye-update', methods=['POST'])
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def giris_irsaliye_update():
    """Giriş İrsaliyesi güncelleme."""
    try:
        evrak_id = request.json.get('evrak_id')

        if not evrak_id:
            return jsonify({'success': False, 'message': 'Evrak ID gereklidir.'})

        conn = get_db_connection4()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE URUN_HAREKETLERI 
            SET Fifo_Maliyet = 0 
            WHERE Fifo_Maliyet = 1 AND Evrak_Id = ?
        """, (evrak_id,))

        affected_rows = cursor.rowcount
        conn.commit()

        # Log action
        log_user_action(session['user_id'], 'GIRIS_IRSALIYE_GUNCELLE',
                        f'Giriş İrsaliyesi güncellendi: Evrak ID={evrak_id}')

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'{affected_rows} kayıt güncellendi.',
            'affected_rows': affected_rows
        })

    except Exception as e:
        return jsonify({'success': False, 'message': f'Güncelleme sırasında hata: {str(e)}'})


# Global değişken process takibi için
active_processes = {}


@app.route('/petrol-barkopos-guncelleme/transfer-to-logo', methods=['POST'])
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def transfer_to_logo():
    """PetrolLogoTumAktarimlar.exe uygulamasını başlat."""
    import subprocess
    import os
    import threading
    import time

    try:
        user_id = session['user_id']

        # Eğer kullanıcının zaten çalışan bir işlemi varsa
        if user_id in active_processes and active_processes[user_id]['process'].poll() is None:
            return jsonify({
                'success': False,
                'message': 'Zaten bir aktarım işlemi devam ediyor.'
            })

        # Farklı olası dosya yolları
        possible_paths = [
            r"C:\Program Files (x86)\Default Company Name\Barkopos-LogoStokIrsaliyeZRapor\PetrolLogoTumAktarimlar.exe",
            r"C:\Program Files\Default Company Name\Barkopos-LogoStokIrsaliyeZRapor\PetrolLogoTumAktarimlar.exe",
            r"C:\Program Files (x86)\Default Company Name\PetrolLogoTumAktarimlar.exe",
            r"C:\Program Files\Default Company Name\PetrolLogoTumAktarimlar.exe",
        ]

        # Ana dizinleri kontrol et
        base_dirs = [
            r"C:\Program Files (x86)\Default Company Name\Barkopos-LogoStokIrsaliyeZRapor",
            r"C:\Program Files\Default Company Name\Barkopos-LogoStokIrsaliyeZRapor",
        ]

        found_path = None

        # Önce belirtilen yolları kontrol et
        for path in possible_paths:
            if os.path.exists(path):
                found_path = path
                break

        # Eğer bulunamazsa dizinlerde ara
        if not found_path:
            for base_dir in base_dirs:
                if os.path.exists(base_dir):
                    for file in os.listdir(base_dir):
                        if file.lower() == 'petrollogotumaktarimlar.exe':
                            found_path = os.path.join(base_dir, file)
                            break
                    if found_path:
                        break

        if not found_path:
            # Detaylı hata mesajı
            error_message = "PetrolLogoTumAktarimlar.exe dosyası bulunamadı.\n\nKontrol edilen yollar:\n"
            for path in possible_paths:
                error_message += f"- {path} (Var: {os.path.exists(path)})\n"

            # Dizin içeriklerini göster
            for base_dir in base_dirs:
                if os.path.exists(base_dir):
                    error_message += f"\nDizin içeriği ({base_dir}):\n"
                    try:
                        files = [f for f in os.listdir(base_dir) if f.lower().endswith('.exe')]
                        for file in files:
                            error_message += f"- {file}\n"
                    except Exception as e:
                        error_message += f"Dizin okunamadı: {str(e)}\n"

            return jsonify({
                'success': False,
                'message': error_message
            })

        # Process'i başlat
        try:
            process = subprocess.Popen([found_path], shell=True)

            # Active processes'e ekle
            active_processes[user_id] = {
                'process': process,
                'start_time': time.time(),
                'exe_path': found_path,
                'status': 'running'
            }

            # Log action
            log_user_action(user_id, 'LOGO_VERI_AKTAR_BASLA', f'PetrolLogoTumAktarimlar.exe başlatıldı: {found_path}')

            return jsonify({
                'success': True,
                'message': 'Veri aktarım işlemi başlatıldı.',
                'process_started': True,
                'exe_path': found_path
            })

        except Exception as run_error:
            return jsonify({
                'success': False,
                'message': f'Program çalıştırılırken hata oluştu: {str(run_error)}\nDosya yolu: {found_path}'
            })

    except Exception as e:
        print(f"Logo veri aktarımı sırasında hata: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Veri aktarımı sırasında hata oluştu: {str(e)}'
        })


@app.route('/petrol-barkopos-guncelleme/check-process-status', methods=['GET'])
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def check_process_status():
    """Aktarım işleminin durumunu kontrol et."""
    import time

    user_id = session['user_id']

    if user_id not in active_processes:
        return jsonify({
            'success': True,
            'status': 'not_running',
            'message': 'Aktif işlem bulunamadı.'
        })

    process_info = active_processes[user_id]
    process = process_info['process']

    # Process'in durumunu kontrol et
    return_code = process.poll()

    if return_code is None:
        # Process hala çalışıyor
        elapsed_time = int(time.time() - process_info['start_time'])
        return jsonify({
            'success': True,
            'status': 'running',
            'message': 'Aktarım işlemi devam ediyor...',
            'elapsed_time': elapsed_time,
            'exe_path': process_info['exe_path']
        })
    else:
        # Process bitti
        elapsed_time = int(time.time() - process_info['start_time'])

        # Log completion
        if return_code == 0:
            log_user_action(user_id, 'LOGO_VERI_AKTAR_TAMAMLA',
                            f'PetrolLogoTumAktarimlar.exe başarıyla tamamlandı. Süre: {elapsed_time}s, Return code: {return_code}')
            status_message = 'Veri aktarım işlemi başarıyla tamamlandı!'
        else:
            log_user_action(user_id, 'LOGO_VERI_AKTAR_HATA',
                            f'PetrolLogoTumAktarimlar.exe hata ile sonlandı. Süre: {elapsed_time}s, Return code: {return_code}')
            status_message = f'Veri aktarım işlemi hata ile sonlandı. (Çıkış kodu: {return_code})'

        # Active processes'ten kaldır
        del active_processes[user_id]

        return jsonify({
            'success': True,
            'status': 'completed',
            'return_code': return_code,
            'elapsed_time': elapsed_time,
            'message': status_message
        })


@app.route('/petrol-barkopos-guncelleme/stop-process', methods=['POST'])
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def stop_transfer_process():
    """Aktarım işlemini durdur."""
    import time

    user_id = session['user_id']

    if user_id not in active_processes:
        return jsonify({
            'success': False,
            'message': 'Durdurulacak aktif işlem bulunamadı.'
        })

    try:
        process_info = active_processes[user_id]
        process = process_info['process']

        if process.poll() is None:  # Process hala çalışıyor
            process.terminate()  # Önce nazikçe sonlandırmayı dene

            # 5 saniye bekle
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Zorla sonlandır
                process.kill()
                process.wait()

            elapsed_time = int(time.time() - process_info['start_time'])

            # Log action
            log_user_action(user_id, 'LOGO_VERI_AKTAR_DURDUR',
                            f'PetrolLogoTumAktarimlar.exe kullanıcı tarafından durduruldu. Süre: {elapsed_time}s')

            # Active processes'ten kaldır
            del active_processes[user_id]

            return jsonify({
                'success': True,
                'message': 'Aktarım işlemi durduruldu.',
                'elapsed_time': elapsed_time
            })
        else:
            # Process zaten bitti
            del active_processes[user_id]
            return jsonify({
                'success': False,
                'message': 'İşlem zaten sonlanmış.'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'İşlem durdurulurken hata oluştu: {str(e)}'
        })


# Debug için dosya yollarını kontrol etmek için ek route
@app.route('/petrol-barkopos-guncelleme/check-files', methods=['GET'])
@login_required
@permission_required(menu_id=1017, permission_type='edit')
def check_barko_files():
    """Debug için dosya yollarını kontrol et."""
    import os

    try:
        # Kontrol edilecek dizinler
        base_dirs = [
            r"C:\Program Files (x86)\Default Company Name\Barkopos-LogoStokIrsaliyeZRapor",
            r"C:\Program Files\Default Company Name\Barkopos-LogoStokIrsaliyeZRapor",
            r"C:\Program Files (x86)\Default Company Name",
            r"C:\Program Files\Default Company Name"
        ]

        result = {
            'directories': {},
            'found_files': []
        }

        for base_dir in base_dirs:
            result['directories'][base_dir] = {
                'exists': os.path.exists(base_dir),
                'files': []
            }

            if os.path.exists(base_dir):
                try:
                    files = os.listdir(base_dir)
                    result['directories'][base_dir]['files'] = files

                    # PetrolLogoTumAktarimlar ile ilgili dosyaları ara
                    for file in files:
                        if 'petrollogo' in file.lower() or 'aktarim' in file.lower() or file.lower().endswith('.exe'):
                            full_path = os.path.join(base_dir, file)
                            result['found_files'].append({
                                'name': file,
                                'path': full_path,
                                'is_file': os.path.isfile(full_path),
                                'is_dir': os.path.isdir(full_path)
                            })
                except Exception as e:
                    result['directories'][base_dir]['error'] = str(e)

        return jsonify({
            'success': True,
            'result': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Add these routes to app.py

@app.route('/barkopos-tum-girisler')
@login_required
@permission_required(menu_id=1018, permission_type='view')
def barkopos_tum_girisler():
    """Barkopos Tüm Girişler sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    return render_template('barkopos_tum_girisler.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions)


@app.route('/barkopos-tum-girisler/giris-data')
@login_required
@permission_required(menu_id=1018, permission_type='view')
def barkopos_giris_data():
    """Giriş İrsaliyesi verilerini getir."""
    try:
        conn = get_db_connection4()  # Barkopos veritabanı bağlantısı
        cursor = conn.cursor()

        query = """
            SELECT 
                CONVERT(VARCHAR(10), HAR.Tarih, 104) AS Tarih, 
                HAR.Evrak_Id,
                CARI.Unvan,
                SUM(HAR.Evrak_Miktar) AS Toplam_Miktar,
                SUM(HAR.Orj_Maliyet) AS Toplam_Maliyet,
                CASE 
                    WHEN HAR.Fifo_Maliyet = 0 THEN 'Bekliyor'
                    WHEN HAR.Fifo_Maliyet = 1 THEN 'Logoya Aktarıldı'
                    ELSE 'Bilinmiyor'
                END AS Durum
            FROM URUN_HAREKETLERI HAR
            LEFT OUTER JOIN URUNLER URN ON URN.StokKod = HAR.StokKodu
            LEFT OUTER JOIN CARI_HESAP_HAREKETLERI CHA ON CHA.Evrak_Id = HAR.Evrak_Id
            LEFT OUTER JOIN CARILER CARI ON CARI.Id = CHA.Cari_Id
            WHERE CARI.Unvan IS NOT NULL
              AND HAR.Tarih >= '2025-05-01'
            GROUP BY 
                CONVERT(VARCHAR(10), HAR.Tarih, 104),
                HAR.Evrak_Id,
                CARI.Unvan,
                HAR.Fifo_Maliyet
            ORDER BY 
                CONVERT(VARCHAR(10), HAR.Tarih, 104) DESC
        """

        cursor.execute(query)

        result = []
        while True:
            row = cursor.fetchone()
            if not row:
                break
            result.append({
                'tarih': row[0],
                'evrak_id': row[1],
                'unvan': row[2] or '',
                'toplam_miktar': float(row[3]) if row[3] else 0,
                'toplam_maliyet': float(row[4]) if row[4] else 0,
                'durum': row[5]
            })

        cursor.close()
        conn.close()

        # Log action
        log_user_action(session['user_id'], 'BARKOPOS_GIRIS_DATA', 'Barkopos giriş irsaliyesi verileri görüntülendi')

        return jsonify({'success': True, 'data': result})

    except Exception as e:
        print(f"Barkopos giriş verileri alınırken hata: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/barkopos-tum-girisler/zrapor-data')
@login_required
@permission_required(menu_id=1018, permission_type='view')
def barkopos_zrapor_data():
    """Z Rapor verilerini getir."""
    try:
        conn = get_db_connection4()  # Barkopos veritabanı bağlantısı
        cursor = conn.cursor()

        query = """
            SELECT 
                CONVERT(VARCHAR(10), HAR.Tarih, 104) AS Tarih,
                CASE 
                    WHEN HAR.Karsilanan_Miktar = 1 THEN 'Logoya Aktarıldı'
                    WHEN HAR.Karsilanan_Miktar = 0 THEN 'Bekliyor'
                    ELSE 'Bilinmiyor'
                END AS Durum,
                SUM(HAR.Evrak_Miktar) AS Toplam_Miktar,
                SUM(HAR.Ana_Fiyat) AS Toplam_Fiyat
            FROM URUN_HAREKETLERI HAR
            LEFT OUTER JOIN URUNLER URN ON URN.StokKod = HAR.StokKodu
            LEFT OUTER JOIN EVRAKLAR E ON E.Id = HAR.Evrak_Id 
            WHERE HAR.Karsilanan_Miktar IN (0, 1)
              AND E.Evrak_Tipi = 11
              AND HAR.Tarih >= '2025-05-01'
            GROUP BY 
                CONVERT(VARCHAR(10), HAR.Tarih, 104),
                HAR.Karsilanan_Miktar
            ORDER BY 
                CONVERT(VARCHAR(10), HAR.Tarih, 104) DESC
        """

        cursor.execute(query)

        result = []
        while True:
            row = cursor.fetchone()
            if not row:
                break
            result.append({
                'tarih': row[0],
                'durum': row[1],
                'toplam_miktar': float(row[2]) if row[2] else 0,
                'toplam_fiyat': float(row[3]) if row[3] else 0
            })

        cursor.close()
        conn.close()

        # Log action
        log_user_action(session['user_id'], 'BARKOPOS_ZRAPOR_DATA', 'Barkopos Z rapor verileri görüntülendi')

        return jsonify({'success': True, 'data': result})

    except Exception as e:
        print(f"Barkopos Z rapor verileri alınırken hata: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})


# YDC Günlük Rapor Mail sayfası için ana rota
@app.route('/ydc-gunluk-rapor-mail')
@login_required
@permission_required(menu_id=1019, permission_type='view')  # Menü ID'nizi uygun şekilde değiştirin
def ydc_gunluk_rapor_mail():
    """YDC Günlük Rapor Mail sayfasını render eder."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    return render_template('ydc_gunluk_rapor_mail.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions)


# Filtre seçeneklerini getiren API
@app.route('/ydc-gunluk-rapor-mail/filter-options', methods=['GET'])
@login_required
def ydc_gunluk_rapor_mail_filter_options():
    """Rapor filtreleri için seçenekleri döndürür."""
    try:
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()

        # Cari listesi
        cursor.execute("""
            SELECT DISTINCT CARI
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE CARI IS NOT NULL
            ORDER BY CARI
        """)
        cari_list = [row[0] for row in cursor.fetchall()]

        # Muhasebe grup listesi
        cursor.execute("""
            SELECT DISTINCT [Malzeme Grup Kodu] AS MuhasebeGrup
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [Malzeme Grup Kodu] IS NOT NULL
            ORDER BY [Malzeme Grup Kodu]
        """)
        muhasebe_grup_list = [row[0] for row in cursor.fetchall()]

        # Malzeme grup listesi
        cursor.execute("""
            SELECT DISTINCT [Malzeme Grup Kodu] AS MalzemeGrup
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [Malzeme Grup Kodu] IS NOT NULL
            ORDER BY [Malzeme Grup Kodu]
        """)
        malzeme_grup_list = [row[0] for row in cursor.fetchall()]

        # Satış elemanı listesi
        cursor.execute("""
            SELECT DISTINCT [SATIŞ ELEMANI] AS SatisElemani
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [SATIŞ ELEMANI] IS NOT NULL
            ORDER BY [SATIŞ ELEMANI]
        """)
        satis_elemani_list = [row[0] for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'cari_list': cari_list,
            'muhasebe_grup_list': muhasebe_grup_list,
            'malzeme_grup_list': malzeme_grup_list,
            'satis_elemani_list': satis_elemani_list
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 1 verilerini getiren API - Muhasebe Grup Raporu
@app.route('/ydc-gunluk-rapor-mail/report1-data', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_report1_data():
    """Muhasebe Grup Raporu verilerini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        date_str = request.form.get('date', '')

        cari_list = request.form.getlist('cari[]') or []
        muhasebe_grup_list = request.form.getlist('muhasebe_grup[]') or []
        satis_elemani_list = request.form.getlist('satis_elemani[]') or []

        # Tarih formatını kontrol et
        if date_str:
            try:
                selected_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%Y-%m-%d')
            except ValueError:
                selected_date = datetime.now().strftime('%Y-%m-%d')
        else:
            selected_date = datetime.now().strftime('%Y-%m-%d')

        # SQL sorgusu oluştur - GÜNLÜK veri için
        sql_query = """
            SELECT 
                [Malzeme Grup Kodu] AS MuhasebeGrupIsmi,
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE CONVERT(DATE, [TARIH]) = ?
        """

        params = [selected_date]

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if muhasebe_grup_list:
            placeholders = ', '.join(['?' for _ in muhasebe_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(muhasebe_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [Malzeme Grup Kodu] ORDER BY SUM([TUTAR]) DESC"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_brut_kg = 0
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            muhasebe_grup = row[0] or "Belirtilmemiş"
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar = float(row[3]) if row[3] else 0

            # Toplam değerleri hesapla
            total_brut_kg += brut_kg
            total_net_kg += net_kg
            total_tutar += tutar

            # Birim fiyatları hesapla
            brut_ort_fiyat = tutar / brut_kg if brut_kg > 0 else 0
            net_ort_fiyat = tutar / net_kg if net_kg > 0 else 0

            result.append({
                'muhasebe_grup_ismi': muhasebe_grup,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar,
                'brut_ort_fiyat': brut_ort_fiyat,
                'net_ort_fiyat': net_ort_fiyat
            })

        cursor.close()
        conn.close()

        # Genel toplam değerlerini hesapla
        avg_brut_price = total_tutar / total_brut_kg if total_brut_kg > 0 else 0
        avg_net_price = total_tutar / total_net_kg if total_net_kg > 0 else 0

        # Debugging için log ekleyelim
        print(f"Query executed with date: {selected_date}")
        print(f"Found {len(result)} records, total amount: {total_tutar}")

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'total_brut_kg': total_brut_kg,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar,
                'avg_brut_price': avg_brut_price,
                'avg_net_price': avg_net_price
            }
        })

    except Exception as e:
        print(f"Error in report1-data: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 2 verilerini getiren API - Detaylı Satış Raporu
@app.route('/ydc-gunluk-rapor-mail/report2-data', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_report2_data():
    """Detaylı Satış Raporu verilerini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        date_str = request.form.get('date', '')
        cari_list = request.form.getlist('cari[]') or []
        malzeme_grup_list = request.form.getlist('malzeme_grup[]') or []
        satis_elemani_list = request.form.getlist('satis_elemani[]') or []

        # Tarih formatını kontrol et
        if date_str:
            try:
                selected_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%Y-%m-%d')
            except ValueError:
                selected_date = datetime.now().strftime('%Y-%m-%d')
        else:
            selected_date = datetime.now().strftime('%Y-%m-%d')

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [CARI],
                [SATIŞ ELEMANI],
                [Malzeme Grup Kodu],
                [URUN_HIZMET_AD],
                [BRÜT_KG],
                [NET_KG],
                [FİRE KG],
                [HURDA],
                [Döviz Türü],
                [DOVIZ_TOPLAM],
                [TUTAR],
                [VADE],
                CONVERT(VARCHAR(10), [TESLİM TARİHİ], 103) AS TeslimTarihi,
                CONVERT(VARCHAR(10), [İRSALİYE TARİHİ], 103) AS IrsaliyeTarihi,
                [TESLİM DURUM],
                [Faturalanma Durumu],
                [Ödeme Durumu]
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE CONVERT(DATE, [TARIH]) = ?
        """

        params = [selected_date]

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " ORDER BY [CARI], [URUN_HIZMET_AD]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []

        for row in cursor.fetchall():
            cari = row[0] or ""
            satis_elemani = row[1] or ""
            malzeme_grup = row[2] or ""
            urun_adi = row[3] or ""
            brut_kg = float(row[4]) if row[4] else 0
            net_kg = float(row[5]) if row[5] else 0
            fire_kg = float(row[6]) if row[6] else 0
            hurda = float(row[7]) if row[7] else 0
            doviz = row[8] or "TL"
            dovizli_tutar = float(row[9]) if row[9] else 0
            tutar_tl = float(row[10]) if row[10] else 0
            vade = row[11] or ""
            teslim_tarihi = row[12] or ""
            irsaliye_tarihi = row[13] or ""
            teslim_durum = row[14] or ""
            fatura_durumu = row[15] or ""
            odeme_durumu = row[16] or ""

            # Birim fiyatları hesapla
            brut_ort_fiyat_tl = tutar_tl / brut_kg if brut_kg > 0 else 0
            net_ort_fiyat_tl = tutar_tl / net_kg if net_kg > 0 else 0
            brut_ort_fiyat_doviz = dovizli_tutar / brut_kg if brut_kg > 0 and dovizli_tutar > 0 else 0
            net_ort_fiyat_doviz = dovizli_tutar / net_kg if net_kg > 0 and dovizli_tutar > 0 else 0

            result.append({
                'cari': cari,
                'satis_elemani': satis_elemani,
                'malzeme_grup': malzeme_grup,
                'urun_adi': urun_adi,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'fire_kg': fire_kg,
                'hurda': hurda,
                'brut_ort_fiyat_tl': brut_ort_fiyat_tl,
                'net_ort_fiyat_tl': net_ort_fiyat_tl,
                'brut_ort_fiyat_doviz': brut_ort_fiyat_doviz,
                'net_ort_fiyat_doviz': net_ort_fiyat_doviz,
                'doviz': doviz,
                'dovizli_tutar': dovizli_tutar,
                'tutar_tl': tutar_tl,
                'vade': vade,
                'teslim_tarihi': teslim_tarihi,
                'irsaliye_tarihi': irsaliye_tarihi,
                'teslim_durum': teslim_durum,
                'fatura_durumu': fatura_durumu,
                'odeme_durumu': odeme_durumu
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 3 verilerini getiren API - Günlük Hedef Raporu
@app.route('/ydc-gunluk-rapor-mail/report3-data', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_report3_data():
    """Günlük Hedef Raporu verilerini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        month_str = request.form.get('month', '')
        cari_list = request.form.getlist('cari[]') or []
        muhasebe_grup_list = request.form.getlist('muhasebe_grup[]') or []
        satis_elemani_list = request.form.getlist('satis_elemani[]') or []

        # Ay formatını kontrol et
        if month_str:
            try:
                # Ay formatı: YYYY-MM
                year, month = map(int, month_str.split('-'))
                first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
                # Ayın son gününü bul
                _, last_day_of_month = calendar.monthrange(year, month)
                last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')
            except (ValueError, IndexError):
                now = datetime.now()
                year, month = now.year, now.month
                first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
                _, last_day_of_month = calendar.monthrange(year, month)
                last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')
        else:
            now = datetime.now()
            year, month = now.year, now.month
            first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
            _, last_day_of_month = calendar.monthrange(year, month)
            last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                CONVERT(VARCHAR(10), [TARIH], 103) AS Tarih,
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE CONVERT(DATE, [TARIH]) BETWEEN ? AND ?
        """

        params = [first_day, last_day]

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if muhasebe_grup_list:
            placeholders = ', '.join(['?' for _ in muhasebe_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(muhasebe_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [TARIH] ORDER BY [TARIH]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_brut_kg = 0
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            tarih = row[0] or ""
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar_tl = float(row[3]) if row[3] else 0

            # Toplam değerler
            total_brut_kg += brut_kg
            total_net_kg += net_kg
            total_tutar += tutar_tl

            # Birim fiyatları hesapla
            brut_ort_fiyat = tutar_tl / brut_kg if brut_kg > 0 else 0
            net_ort_fiyat = tutar_tl / net_kg if net_kg > 0 else 0

            result.append({
                'tarih': tarih,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl,
                'brut_ort_fiyat': brut_ort_fiyat,
                'net_ort_fiyat': net_ort_fiyat
            })

        cursor.close()
        conn.close()

        # Günlük ortalamalar hesapla
        day_count = len(result) if result else 1
        avg_daily_brut_kg = total_brut_kg / day_count
        avg_daily_net_kg = total_net_kg / day_count
        avg_daily_brut_price = total_tutar / total_brut_kg if total_brut_kg > 0 else 0
        avg_daily_net_price = total_tutar / total_net_kg if total_net_kg > 0 else 0
        avg_daily_amount = total_tutar / day_count

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'avg_daily_brut_kg': avg_daily_brut_kg,
                'avg_daily_net_kg': avg_daily_net_kg,
                'avg_daily_brut_price': avg_daily_brut_price,  # Eklendi
                'avg_daily_net_price': avg_daily_net_price,  # Eklendi
                'avg_daily_amount': avg_daily_amount,
                'total_brut_kg': total_brut_kg,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 4 verilerini getiren API - Aylık Hedef Raporu
@app.route('/ydc-gunluk-rapor-mail/report4-data', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_report4_data():
    """Aylık Hedef Raporu verilerini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')
        cari_list = request.form.getlist('cari[]') or []
        muhasebe_grup_list = request.form.getlist('muhasebe_grup[]') or []
        satis_elemani_list = request.form.getlist('satis_elemani[]') or []

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [AY],
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
        """

        params = [year]

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if muhasebe_grup_list:
            placeholders = ', '.join(['?' for _ in muhasebe_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(muhasebe_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [AY] ORDER BY [AY]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Ay isimlerini hazırla
        ay_isimleri = [
            "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
            "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"
        ]

        # Sonuçları al ve işle
        result = []
        total_brut_kg = 0
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            ay_no = int(row[0]) if row[0] else 0
            ay_name = ay_isimleri[ay_no - 1] if 1 <= ay_no <= 12 else f"Ay {ay_no}"
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar_tl = float(row[3]) if row[3] else 0

            # Toplam değerler
            total_brut_kg += brut_kg
            total_net_kg += net_kg
            total_tutar += tutar_tl

            # Birim fiyatları hesapla
            brut_ort_fiyat = tutar_tl / brut_kg if brut_kg > 0 else 0
            net_ort_fiyat = tutar_tl / net_kg if net_kg > 0 else 0

            result.append({
                'ay': str(ay_no),
                'ay_name': ay_name,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl,
                'brut_ort_fiyat': brut_ort_fiyat,
                'net_ort_fiyat': net_ort_fiyat
            })

        cursor.close()
        conn.close()

        # Aylık ortalamalar hesapla
        month_count = len(result) if result else 1
        avg_monthly_brut_kg = total_brut_kg / month_count
        avg_monthly_net_kg = total_net_kg / month_count
        avg_monthly_brut_price = total_tutar / total_brut_kg if total_brut_kg > 0 else 0
        avg_monthly_net_price = total_tutar / total_net_kg if total_net_kg > 0 else 0
        avg_monthly_amount = total_tutar / month_count

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'avg_monthly_brut_kg': avg_monthly_brut_kg,
                'avg_monthly_net_kg': avg_monthly_net_kg,
                'avg_monthly_brut_price': avg_monthly_brut_price,  # Eklendi
                'avg_monthly_net_price': avg_monthly_net_price,  # Eklendi
                'avg_monthly_amount': avg_monthly_amount,
                'total_brut_kg': total_brut_kg,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 5 - Top Customers by TL
@app.route('/ydc-gunluk-rapor-mail/top-customers-by-tl', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_top_customers_by_tl():
    """En çok satış yapılan müşteriler - Tutar TL bazında"""
    try:
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        sql_query = """
            SELECT 
                [CARI],
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
        """
        params = [year]

        if month_str != '0':
            month = int(month_str)
            if 1 <= month <= 12:
                sql_query += " AND [AY] = ?"
                params.append(month)

        sql_query += """
            GROUP BY [CARI]
            ORDER BY SUM([TUTAR]) DESC
        """

        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        all_data = []
        total_amount = 0
        total_kg = 0

        for row in cursor.fetchall():
            cari = row[0] or "Belirtilmemiş"
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar_tl = float(row[3]) if row[3] else 0

            all_data.append({
                'cari': cari,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl
            })

            total_amount += tutar_tl
            total_kg += net_kg

        cursor.close()
        conn.close()

        # Top N veriyi al ve yüzde hesapla
        result = []
        for i, item in enumerate(all_data[:top_count]):
            pay = (item['tutar_tl'] / total_amount * 100) if total_amount > 0 else 0
            result.append({
                'sira': i + 1,
                'cari': item['cari'],
                'brut_kg': item['brut_kg'],
                'net_kg': item['net_kg'],
                'tutar_tl': item['tutar_tl'],
                'pay': pay
            })

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'total_amount': total_amount,
                'total_kg': total_kg
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 5 - Top Customers by KG
@app.route('/ydc-gunluk-rapor-mail/top-customers-by-kg', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_top_customers_by_kg():
    """En çok satış yapılan müşteriler - Net KG bazında"""
    try:
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        sql_query = """
            SELECT 
                [CARI],
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
        """
        params = [year]

        if month_str != '0':
            month = int(month_str)
            if 1 <= month <= 12:
                sql_query += " AND [AY] = ?"
                params.append(month)

        sql_query += """
            GROUP BY [CARI]
            ORDER BY SUM([NET_KG]) DESC
        """

        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        all_data = []
        total_amount = 0
        total_kg = 0

        for row in cursor.fetchall():
            cari = row[0] or "Belirtilmemiş"
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar_tl = float(row[3]) if row[3] else 0

            all_data.append({
                'cari': cari,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl
            })

            total_amount += tutar_tl
            total_kg += net_kg

        cursor.close()
        conn.close()

        # Top N veriyi al ve yüzde hesapla
        result = []
        for i, item in enumerate(all_data[:top_count]):
            pay = (item['net_kg'] / total_kg * 100) if total_kg > 0 else 0
            result.append({
                'sira': i + 1,
                'cari': item['cari'],
                'brut_kg': item['brut_kg'],
                'net_kg': item['net_kg'],
                'tutar_tl': item['tutar_tl'],
                'pay': pay
            })

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'total_amount': total_amount,
                'total_kg': total_kg
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 5 - Top Material Groups by TL
@app.route('/ydc-gunluk-rapor-mail/top-material-groups-by-tl', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_top_material_groups_by_tl():
    """En çok satılan malzeme grupları - Tutar TL bazında"""
    try:
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        sql_query = """
            SELECT 
                [Malzeme Grup Kodu],
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
        """
        params = [year]

        if month_str != '0':
            month = int(month_str)
            if 1 <= month <= 12:
                sql_query += " AND [AY] = ?"
                params.append(month)

        sql_query += """
            GROUP BY [Malzeme Grup Kodu]
            ORDER BY SUM([TUTAR]) DESC
        """

        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        all_data = []
        total_amount = 0

        for row in cursor.fetchall():
            malzeme_grup = row[0] or "Belirtilmemiş"
            tutar_tl = float(row[1]) if row[1] else 0

            all_data.append({
                'malzeme_grup': malzeme_grup,
                'tutar_tl': tutar_tl
            })

            total_amount += tutar_tl

        cursor.close()
        conn.close()

        # Top N veriyi al ve yüzde hesapla
        result = []
        for i, item in enumerate(all_data[:top_count]):
            pay = (item['tutar_tl'] / total_amount * 100) if total_amount > 0 else 0
            result.append({
                'sira': i + 1,
                'malzeme_grup': item['malzeme_grup'],
                'tutar_tl': item['tutar_tl'],
                'pay': pay
            })

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 5 - Top Material Groups by KG
@app.route('/ydc-gunluk-rapor-mail/top-material-groups-by-kg', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_top_material_groups_by_kg():
    """En çok satılan malzeme grupları - Net KG bazında"""
    try:
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        sql_query = """
            SELECT 
                [Malzeme Grup Kodu],
                SUM([NET_KG]) AS NetKg
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
        """
        params = [year]

        if month_str != '0':
            month = int(month_str)
            if 1 <= month <= 12:
                sql_query += " AND [AY] = ?"
                params.append(month)

        sql_query += """
            GROUP BY [Malzeme Grup Kodu]
            ORDER BY SUM([NET_KG]) DESC
        """

        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        all_data = []
        total_kg = 0

        for row in cursor.fetchall():
            malzeme_grup = row[0] or "Belirtilmemiş"
            net_kg = float(row[1]) if row[1] else 0

            all_data.append({
                'malzeme_grup': malzeme_grup,
                'net_kg': net_kg
            })

            total_kg += net_kg

        cursor.close()
        conn.close()

        # Top N veriyi al ve yüzde hesapla
        result = []
        for i, item in enumerate(all_data[:top_count]):
            pay = (item['net_kg'] / total_kg * 100) if total_kg > 0 else 0
            result.append({
                'sira': i + 1,
                'malzeme_grup': item['malzeme_grup'],
                'net_kg': item['net_kg'],
                'pay': pay
            })

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 5 - Top Products by TL
@app.route('/ydc-gunluk-rapor-mail/top-products-by-tl', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_top_products_by_tl():
    """En çok satılan ürünler - Tutar TL bazında"""
    try:
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        sql_query = """
            SELECT 
                [URUN_HIZMET_AD],
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
        """
        params = [year]

        if month_str != '0':
            month = int(month_str)
            if 1 <= month <= 12:
                sql_query += " AND [AY] = ?"
                params.append(month)

        sql_query += """
            GROUP BY [URUN_HIZMET_AD]
            ORDER BY SUM([TUTAR]) DESC
        """

        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        all_data = []
        total_amount = 0

        for row in cursor.fetchall():
            urun_adi = row[0] or "Belirtilmemiş"
            tutar_tl = float(row[1]) if row[1] else 0

            all_data.append({
                'urun_adi': urun_adi,
                'tutar_tl': tutar_tl
            })

            total_amount += tutar_tl

        cursor.close()
        conn.close()

        # Top N veriyi al ve yüzde hesapla
        result = []
        for i, item in enumerate(all_data[:top_count]):
            pay = (item['tutar_tl'] / total_amount * 100) if total_amount > 0 else 0
            result.append({
                'sira': i + 1,
                'urun_adi': item['urun_adi'],
                'tutar_tl': item['tutar_tl'],
                'pay': pay
            })

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 5 - Top Products by KG
@app.route('/ydc-gunluk-rapor-mail/top-products-by-kg', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_top_products_by_kg():
    """En çok satılan ürünler - Net KG bazında"""
    try:
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        sql_query = """
            SELECT 
                [URUN_HIZMET_AD],
                SUM([NET_KG]) AS NetKg
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
        """
        params = [year]

        if month_str != '0':
            month = int(month_str)
            if 1 <= month <= 12:
                sql_query += " AND [AY] = ?"
                params.append(month)

        sql_query += """
            GROUP BY [URUN_HIZMET_AD]
            ORDER BY SUM([NET_KG]) DESC
        """

        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        all_data = []
        total_kg = 0

        for row in cursor.fetchall():
            urun_adi = row[0] or "Belirtilmemiş"
            net_kg = float(row[1]) if row[1] else 0

            all_data.append({
                'urun_adi': urun_adi,
                'net_kg': net_kg
            })

            total_kg += net_kg

        cursor.close()
        conn.close()

        # Top N veriyi al ve yüzde hesapla
        result = []
        for i, item in enumerate(all_data[:top_count]):
            pay = (item['net_kg'] / total_kg * 100) if total_kg > 0 else 0
            result.append({
                'sira': i + 1,
                'urun_adi': item['urun_adi'],
                'net_kg': item['net_kg'],
                'pay': pay
            })

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 5 - Monthly Sales Trend
@app.route('/ydc-gunluk-rapor-mail/monthly-sales-trend', methods=['POST'])
@login_required
def ydc_gunluk_rapor_mail_monthly_sales_trend():
    """Aylık satış trendi"""
    try:
        year_str = request.form.get('year', '')

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        sql_query = """
            SELECT 
                [AY],
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
            GROUP BY [AY]
            ORDER BY [AY]
        """

        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, [year])

        # Ay isimlerini hazırla
        ay_isimleri = [
            "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
            "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"
        ]

        result = []
        for row in cursor.fetchall():
            ay_no = int(row[0]) if row[0] else 0
            ay_name = ay_isimleri[ay_no - 1] if 1 <= ay_no <= 12 else f"Ay {ay_no}"
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar_tl = float(row[3]) if row[3] else 0

            result.append({
                'ay': str(ay_no),
                'ay_name': ay_name,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# YDC Günlük Rapor Mail Gönderme - Güncellenmiş Backend Kodu
@app.route('/ydc-gunluk-rapor-mail/send-mail', methods=['POST'])
@login_required
@permission_required(menu_id=1019, permission_type='view')
def ydc_gunluk_rapor_mail_send_mail():
    """Tüm raporları HTML formatında mail olarak gönderir."""
    try:
        # JSON verisini al
        mail_data = request.get_json()

        if not mail_data:
            return jsonify({
                'success': False,
                'error': 'Mail verisi alınamadı'
            })

        # Gmail SMTP ayarları
        sender_email = "yagcilarholding1@gmail.com"
        sender_password = "bqnp sius nztz padc"
        sender_name = "Yağcılar Holding"  # YENİ: Gönderen adı

        recipients = []
        cc_recipients = []

        # Alıcı listesini hazırla
        if isinstance(mail_data.get('recipients'), list):
            recipients = [email.strip() for email in mail_data['recipients'] if email.strip()]
        else:
            recipients = ["dogukanturan@ydcmetal.com.tr"]

        # CC alıcı listesini hazırla - YENİ
        if isinstance(mail_data.get('cc_recipients'), list):
            cc_recipients = [email.strip() for email in mail_data['cc_recipients'] if email.strip()]

        if not recipients:
            return jsonify({
                'success': False,
                'error': 'Geçerli alıcı e-posta adresi bulunamadı'
            })

        # E-posta konteyneri oluştur
        msg = MIMEMultipart('alternative')
        msg['Subject'] = mail_data.get('subject', 'YDC Günlük Rapor')

        # GÜNCELLEME: Gönderen adını "Yağcılar Holding" olarak ayarla
        msg['From'] = f"{sender_name}"

        msg['To'] = ', '.join(recipients)

        # GÜNCELLEME: CC varsa ekle
        if cc_recipients:
            msg['Cc'] = ', '.join(cc_recipients)

        # Rapor verilerini topla
        report_data = {}
        include_reports = mail_data.get('include_reports', {})
        filters = mail_data.get('filters', {})

        # Rapor 1 - Muhasebe Grup Raporu
        if include_reports.get('report1', True):
            report_data['report1'] = get_report1_data_for_mail(filters.get('report1', {}))

        # Rapor 2 - Detaylı Satış Raporu
        if include_reports.get('report2', True):
            report_data['report2'] = get_report2_data_for_mail(filters.get('report2', {}))

        # Rapor 3 - Günlük Hedef Raporu
        if include_reports.get('report3', True):
            report_data['report3'] = get_report3_data_for_mail(filters.get('report3', {}))

        # Rapor 4 - Aylık Hedef Raporu
        if include_reports.get('report4', True):
            report_data['report4'] = get_report4_data_for_mail(filters.get('report4', {}))

        # Rapor 5 - Genel Analiz Raporu
        if include_reports.get('report5', False):
            report_data['report5'] = get_report5_data_for_mail(
                filters.get('report5', {'year': datetime.now().year, 'month': '0', 'top_count': 20}))

        # HTML mail içeriğini oluştur
        html_content = generate_mail_html(report_data, mail_data.get('note', ''), include_reports)

        # HTML içeriği ekle
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(html_part)

        # Gmail SMTP ile mail gönder
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Gmail için TLS gerekli
        server.login(sender_email, sender_password)

        # Tüm alıcı listesini birleştir (TO + CC)
        all_recipients = recipients + cc_recipients

        for recipient in all_recipients:
            server.sendmail(sender_email, recipient, msg.as_string())

        server.quit()

        # Başarı mesajını güncelle
        total_recipients = len(recipients)
        total_cc = len(cc_recipients)

        success_message = f'Mail başarıyla {total_recipients} alıcıya gönderildi'
        if total_cc > 0:
            success_message += f' ve {total_cc} CC alıcısına gönderildi'

        return jsonify({
            'success': True,
            'message': success_message
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Mail gönderilirken hata oluştu: {str(e)}'
        })


def get_report1_data_for_mail(filters):
    """Mail için Rapor 1 verilerini getirir"""
    try:
        # Tarih formatını kontrol et
        date_str = filters.get('date', '')
        if date_str:
            try:
                selected_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%Y-%m-%d')
            except ValueError:
                selected_date = datetime.now().strftime('%Y-%m-%d')
        else:
            selected_date = datetime.now().strftime('%Y-%m-%d')

        # SQL sorgusu oluştur - GÜNLÜK veri için
        sql_query = """
            SELECT 
                [Malzeme Grup Kodu] AS MuhasebeGrupIsmi,
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE CONVERT(DATE, [TARIH]) = ?
        """

        params = [selected_date]
        cari_list = filters.get('cari', [])
        muhasebe_grup_list = filters.get('muhasebe_grup', [])
        satis_elemani_list = filters.get('satis_elemani', [])

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if muhasebe_grup_list:
            placeholders = ', '.join(['?' for _ in muhasebe_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(muhasebe_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [Malzeme Grup Kodu] ORDER BY SUM([TUTAR]) DESC"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        result = []
        total_brut_kg = 0
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            muhasebe_grup = row[0] or "Belirtilmemiş"
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar = float(row[3]) if row[3] else 0

            total_brut_kg += brut_kg
            total_net_kg += net_kg
            total_tutar += tutar

            brut_ort_fiyat = tutar / brut_kg if brut_kg > 0 else 0
            net_ort_fiyat = tutar / net_kg if net_kg > 0 else 0

            result.append({
                'muhasebe_grup_ismi': muhasebe_grup,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar,
                'brut_ort_fiyat': brut_ort_fiyat,
                'net_ort_fiyat': net_ort_fiyat
            })

        cursor.close()
        conn.close()

        avg_brut_price = total_tutar / total_brut_kg if total_brut_kg > 0 else 0
        avg_net_price = total_tutar / total_net_kg if total_net_kg > 0 else 0

        return {
            'data': result,
            'summary': {
                'total_brut_kg': total_brut_kg,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar,
                'avg_brut_price': avg_brut_price,
                'avg_net_price': avg_net_price
            },
            'filters': {
                'date': selected_date
            }
        }

    except Exception as e:
        return {'error': str(e)}


def get_report2_data_for_mail(filters):
    """Mail için Rapor 2 verilerini getirir"""
    try:
        # Tarih formatını kontrol et
        date_str = filters.get('date', '')
        if date_str:
            try:
                selected_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%Y-%m-%d')
            except ValueError:
                selected_date = datetime.now().strftime('%Y-%m-%d')
        else:
            selected_date = datetime.now().strftime('%Y-%m-%d')

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [CARI],
                [SATIŞ ELEMANI],
                [Malzeme Grup Kodu],
                [URUN_HIZMET_AD],
                [BRÜT_KG],
                [NET_KG],
                [FİRE KG],
                [HURDA],
                [Döviz Türü],
                [DOVIZ_TOPLAM],
                [TUTAR],
                [VADE],
                CONVERT(VARCHAR(10), [TESLİM TARİHİ], 103) AS TeslimTarihi,
                CONVERT(VARCHAR(10), [İRSALİYE TARİHİ], 103) AS IrsaliyeTarihi,
                [TESLİM DURUM],
                [Faturalanma Durumu],
                [Ödeme Durumu]
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE CONVERT(DATE, [TARIH]) = ?
        """

        params = [selected_date]
        cari_list = filters.get('cari', [])
        malzeme_grup_list = filters.get('malzeme_grup', [])
        satis_elemani_list = filters.get('satis_elemani', [])

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " ORDER BY [CARI], [URUN_HIZMET_AD]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        result = []
        for row in cursor.fetchall():
            cari = row[0] or ""
            satis_elemani = row[1] or ""
            malzeme_grup = row[2] or ""
            urun_adi = row[3] or ""
            brut_kg = float(row[4]) if row[4] else 0
            net_kg = float(row[5]) if row[5] else 0
            fire_kg = float(row[6]) if row[6] else 0
            hurda = float(row[7]) if row[7] else 0
            doviz = row[8] or "TL"
            dovizli_tutar = float(row[9]) if row[9] else 0
            tutar_tl = float(row[10]) if row[10] else 0
            vade = row[11] or ""
            teslim_tarihi = row[12] or ""
            irsaliye_tarihi = row[13] or ""
            teslim_durum = row[14] or ""
            fatura_durumu = row[15] or ""
            odeme_durumu = row[16] or ""

            # Birim fiyatları hesapla
            brut_ort_fiyat_tl = tutar_tl / brut_kg if brut_kg > 0 else 0
            net_ort_fiyat_tl = tutar_tl / net_kg if net_kg > 0 else 0
            brut_ort_fiyat_doviz = dovizli_tutar / brut_kg if brut_kg > 0 and dovizli_tutar > 0 else 0
            net_ort_fiyat_doviz = dovizli_tutar / net_kg if net_kg > 0 and dovizli_tutar > 0 else 0

            result.append({
                'cari': cari,
                'satis_elemani': satis_elemani,
                'malzeme_grup': malzeme_grup,
                'urun_adi': urun_adi,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'fire_kg': fire_kg,
                'hurda': hurda,
                'brut_ort_fiyat_tl': brut_ort_fiyat_tl,
                'net_ort_fiyat_tl': net_ort_fiyat_tl,
                'brut_ort_fiyat_doviz': brut_ort_fiyat_doviz,
                'net_ort_fiyat_doviz': net_ort_fiyat_doviz,
                'doviz': doviz,
                'dovizli_tutar': dovizli_tutar,
                'tutar_tl': tutar_tl,
                'vade': vade,
                'teslim_tarihi': teslim_tarihi,
                'irsaliye_tarihi': irsaliye_tarihi,
                'teslim_durum': teslim_durum,
                'fatura_durumu': fatura_durumu,
                'odeme_durumu': odeme_durumu
            })

        cursor.close()
        conn.close()

        return {
            'data': result,
            'filters': {
                'date': selected_date
            }
        }

    except Exception as e:
        return {'error': str(e)}


def get_report3_data_for_mail(filters):
    """Mail için Rapor 3 verilerini getirir"""
    try:
        # Ay formatını kontrol et
        month_str = filters.get('month', '')
        if month_str:
            try:
                year, month = map(int, month_str.split('-'))
                first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
                _, last_day_of_month = calendar.monthrange(year, month)
                last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')
            except (ValueError, IndexError):
                now = datetime.now()
                year, month = now.year, now.month
                first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
                _, last_day_of_month = calendar.monthrange(year, month)
                last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')
        else:
            now = datetime.now()
            year, month = now.year, now.month
            first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
            _, last_day_of_month = calendar.monthrange(year, month)
            last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                CONVERT(VARCHAR(10), [TARIH], 103) AS Tarih,
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE CONVERT(DATE, [TARIH]) BETWEEN ? AND ?
        """

        params = [first_day, last_day]
        cari_list = filters.get('cari', [])
        muhasebe_grup_list = filters.get('muhasebe_grup', [])
        satis_elemani_list = filters.get('satis_elemani', [])

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if muhasebe_grup_list:
            placeholders = ', '.join(['?' for _ in muhasebe_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(muhasebe_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [TARIH] ORDER BY [TARIH]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        result = []
        total_brut_kg = 0
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            tarih = row[0] or ""
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar_tl = float(row[3]) if row[3] else 0

            total_brut_kg += brut_kg
            total_net_kg += net_kg
            total_tutar += tutar_tl

            brut_ort_fiyat = tutar_tl / brut_kg if brut_kg > 0 else 0
            net_ort_fiyat = tutar_tl / net_kg if net_kg > 0 else 0

            result.append({
                'tarih': tarih,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl,
                'brut_ort_fiyat': brut_ort_fiyat,
                'net_ort_fiyat': net_ort_fiyat
            })

        cursor.close()
        conn.close()

        # Günlük ortalamalar
        day_count = len(result) if result else 1
        avg_daily_brut_kg = total_brut_kg / day_count
        avg_daily_net_kg = total_net_kg / day_count
        avg_daily_brut_price = total_tutar / total_brut_kg if total_brut_kg > 0 else 0
        avg_daily_net_price = total_tutar / total_net_kg if total_net_kg > 0 else 0
        avg_daily_amount = total_tutar / day_count

        return {
            'data': result,
            'summary': {
                'avg_daily_brut_kg': avg_daily_brut_kg,
                'avg_daily_net_kg': avg_daily_net_kg,
                'avg_daily_brut_price': avg_daily_brut_price,  # Eklendi
                'avg_daily_net_price': avg_daily_net_price,  # Eklendi
                'avg_daily_amount': avg_daily_amount,
                'total_brut_kg': total_brut_kg,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar
            },
            'filters': {
                'month': month_str,
                'first_day': first_day,
                'last_day': last_day
            }
        }

    except Exception as e:
        return {'error': str(e)}


def get_report4_data_for_mail(filters):
    """Mail için Rapor 4 verilerini getirir"""
    try:
        # Yıl formatını kontrol et
        year_str = filters.get('year', '')
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [AY],
                SUM([BRÜT_KG]) AS BrutKg,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
            WHERE [YIL] = ?
        """

        params = [year]
        cari_list = filters.get('cari', [])
        muhasebe_grup_list = filters.get('muhasebe_grup', [])
        satis_elemani_list = filters.get('satis_elemani', [])

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if muhasebe_grup_list:
            placeholders = ', '.join(['?' for _ in muhasebe_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(muhasebe_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [AY] ORDER BY [AY]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Ay isimlerini hazırla
        ay_isimleri = [
            "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
            "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"
        ]

        result = []
        total_brut_kg = 0
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            ay_no = int(row[0]) if row[0] else 0
            ay_name = ay_isimleri[ay_no - 1] if 1 <= ay_no <= 12 else f"Ay {ay_no}"
            brut_kg = float(row[1]) if row[1] else 0
            net_kg = float(row[2]) if row[2] else 0
            tutar_tl = float(row[3]) if row[3] else 0

            total_brut_kg += brut_kg
            total_net_kg += net_kg
            total_tutar += tutar_tl

            brut_ort_fiyat = tutar_tl / brut_kg if brut_kg > 0 else 0
            net_ort_fiyat = tutar_tl / net_kg if net_kg > 0 else 0

            result.append({
                'ay': str(ay_no),
                'ay_name': ay_name,
                'brut_kg': brut_kg,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl,
                'brut_ort_fiyat': brut_ort_fiyat,
                'net_ort_fiyat': net_ort_fiyat
            })

        cursor.close()
        conn.close()

        # Aylık ortalamalar
        month_count = len(result) if result else 1
        avg_monthly_brut_kg = total_brut_kg / month_count
        avg_monthly_net_kg = total_net_kg / month_count
        avg_monthly_brut_price = total_tutar / total_brut_kg if total_brut_kg > 0 else 0
        avg_monthly_net_price = total_tutar / total_net_kg if total_net_kg > 0 else 0
        avg_monthly_amount = total_tutar / month_count

        return {
            'data': result,
            'summary': {
                'avg_monthly_brut_kg': avg_monthly_brut_kg,
                'avg_monthly_net_kg': avg_monthly_net_kg,
                'avg_monthly_brut_price': avg_monthly_brut_price,  # Eklendi
                'avg_monthly_net_price': avg_monthly_net_price,  # Eklendi
                'avg_monthly_amount': avg_monthly_amount,
                'total_brut_kg': total_brut_kg,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar
            },
            'filters': {
                'year': year
            }
        }

    except Exception as e:
        return {'error': str(e)}


def get_report5_data_for_mail(filters):
    """Mail için Rapor 5 (Genel Analiz Raporu) verilerini getirir"""
    try:
        # Yıl ve ay bilgisini al
        year_str = filters.get('year', '')
        month_str = filters.get('month', '0')
        top_count = int(filters.get('top_count', '20'))

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        # Müşteri verilerini al (TL)
        customers_tl_data = []
        try:
            conn = get_db_connection2()
            cursor = conn.cursor()

            # Top customers by TL query
            sql_query = """
                SELECT 
                    [CARI],
                    SUM([BRÜT_KG]) AS BrutKg,
                    SUM([NET_KG]) AS NetKg,
                    SUM([TUTAR]) AS TutarTL
                FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
                WHERE [YIL] = ?
            """
            params = [year]

            if month_str != '0':
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)

            sql_query += """
                GROUP BY [CARI]
                ORDER BY SUM([TUTAR]) DESC
            """

            cursor.execute(sql_query, params)

            all_tl_data = []
            total_tl_kg = 0
            total_tl_amount = 0

            for row in cursor.fetchall():
                cari = row[0] or "Belirtilmemiş"
                brut_kg = float(row[1]) if row[1] else 0
                net_kg = float(row[2]) if row[2] else 0
                tutar_tl = float(row[3]) if row[3] else 0

                all_tl_data.append({
                    'cari': cari,
                    'brut_kg': brut_kg,
                    'net_kg': net_kg,
                    'tutar_tl': tutar_tl
                })

                total_tl_kg += net_kg
                total_tl_amount += tutar_tl

            # İlk top_count kadar veriyi al
            for i, item in enumerate(all_tl_data[:top_count]):
                pay = (item['tutar_tl'] / total_tl_amount * 100) if total_tl_amount > 0 else 0
                customers_tl_data.append({
                    'sira': i + 1,
                    'cari': item['cari'],
                    'net_kg': item['net_kg'],
                    'tutar_tl': item['tutar_tl'],
                    'pay': pay
                })

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error getting top customers TL data: {str(e)}")

        # Müşteri verilerini al (KG)
        customers_kg_data = []
        try:
            conn = get_db_connection2()
            cursor = conn.cursor()

            # Top customers by KG query
            sql_query = """
                SELECT 
                    [CARI],
                    SUM([BRÜT_KG]) AS BrutKg,
                    SUM([NET_KG]) AS NetKg,
                    SUM([TUTAR]) AS TutarTL
                FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
                WHERE [YIL] = ?
            """
            params = [year]

            if month_str != '0':
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)

            sql_query += """
                GROUP BY [CARI]
                ORDER BY SUM([NET_KG]) DESC
            """

            cursor.execute(sql_query, params)

            all_kg_data = []
            total_kg = 0
            total_kg_amount = 0

            for row in cursor.fetchall():
                cari = row[0] or "Belirtilmemiş"
                brut_kg = float(row[1]) if row[1] else 0
                net_kg = float(row[2]) if row[2] else 0
                tutar_tl = float(row[3]) if row[3] else 0

                all_kg_data.append({
                    'cari': cari,
                    'brut_kg': brut_kg,
                    'net_kg': net_kg,
                    'tutar_tl': tutar_tl
                })

                total_kg += net_kg
                total_kg_amount += tutar_tl

            # İlk top_count kadar veriyi al
            for i, item in enumerate(all_kg_data[:top_count]):
                pay = (item['net_kg'] / total_kg * 100) if total_kg > 0 else 0
                customers_kg_data.append({
                    'sira': i + 1,
                    'cari': item['cari'],
                    'net_kg': item['net_kg'],
                    'tutar_tl': item['tutar_tl'],
                    'pay': pay
                })

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error getting top customers KG data: {str(e)}")

        # Malzeme Grup verilerini al (TL)
        material_groups_tl_data = []
        try:
            conn = get_db_connection2()
            cursor = conn.cursor()

            sql_query = """
                SELECT 
                    [Malzeme Grup Kodu],
                    SUM([TUTAR]) AS TutarTL
                FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
                WHERE [YIL] = ?
            """
            params = [year]

            if month_str != '0':
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)

            sql_query += """
                GROUP BY [Malzeme Grup Kodu]
                ORDER BY SUM([TUTAR]) DESC
            """

            cursor.execute(sql_query, params)

            all_material_tl_data = []
            total_material_tl = 0

            for row in cursor.fetchall():
                malzeme_grup = row[0] or "Belirtilmemiş"
                tutar_tl = float(row[1]) if row[1] else 0

                all_material_tl_data.append({
                    'malzeme_grup': malzeme_grup,
                    'tutar_tl': tutar_tl
                })

                total_material_tl += tutar_tl

            # İlk top_count kadar veriyi al
            for i, item in enumerate(all_material_tl_data[:top_count]):
                pay = (item['tutar_tl'] / total_material_tl * 100) if total_material_tl > 0 else 0
                material_groups_tl_data.append({
                    'sira': i + 1,
                    'malzeme_grup': item['malzeme_grup'],
                    'tutar_tl': item['tutar_tl'],
                    'pay': pay
                })

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error getting top material groups TL data: {str(e)}")

        # Aylık satış trendleri
        monthly_trend_data = []
        try:
            conn = get_db_connection2()
            cursor = conn.cursor()

            sql_query = """
                SELECT 
                    [AY],
                    SUM([BRÜT_KG]) AS BrutKg,
                    SUM([NET_KG]) AS NetKg,
                    SUM([TUTAR]) AS TutarTL
                FROM BYT_TBL_BYT_SATIS_RAPORU_YDC_ERP
                WHERE [YIL] = ?
                GROUP BY [AY]
                ORDER BY [AY]
            """
            params = [year]

            cursor.execute(sql_query, params)

            # Ay isimlerini hazırla
            ay_isimleri = [
                "OCAK", "ŞUBAT", "MART", "NİSAN", "MAYIS", "HAZİRAN",
                "TEMMUZ", "AĞUSTOS", "EYLÜL", "EKİM", "KASIM", "ARALIK"
            ]

            for row in cursor.fetchall():
                ay_no = int(row[0]) if row[0] else 0
                ay_name = ay_isimleri[ay_no - 1] if 1 <= ay_no <= 12 else f"Ay {ay_no}"
                brut_kg = float(row[1]) if row[1] else 0
                net_kg = float(row[2]) if row[2] else 0
                tutar_tl = float(row[3]) if row[3] else 0

                monthly_trend_data.append({
                    'ay': str(ay_no),
                    'ay_name': ay_name,
                    'brut_kg': brut_kg,
                    'net_kg': net_kg,
                    'tutar_tl': tutar_tl
                })

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error getting monthly sales trend data: {str(e)}")

        return {
            'customers_tl': {
                'data': customers_tl_data,
                'summary': {
                    'total_kg': total_tl_kg,
                    'total_amount': total_tl_amount
                }
            },
            'customers_kg': {
                'data': customers_kg_data,
                'summary': {
                    'total_kg': total_kg,
                    'total_amount': total_kg_amount
                }
            },
            'material_groups_tl': {
                'data': material_groups_tl_data
            },
            'monthly_trend': {
                'data': monthly_trend_data
            },
            'filters': {
                'year': year,
                'month': month_str
            }
        }

    except Exception as e:
        return {'error': str(e)}


def format_number(number, decimals=2):
    """Sayıları Türkçe formatta formatlar"""
    if number is None:
        return "0,00"
    return f"{number:,.{decimals}f}".replace(',', 'X').replace('.', ',').replace('X', '.')


def generate_mail_html(report_data, note, include_reports):
    """Mail için HTML içeriğini oluşturur"""

    html_content = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>YDÇ Metal Günlük Rapor</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f8f9fa;
                color: #333;
                line-height: 1.6;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #282965 0%, #1e1a4f 100%);
                color: white;
                text-align: center;
                padding: 30px 20px;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .header p {{
                margin: 10px 0 0 0;
                font-size: 16px;
                opacity: 0.9;
            }}
            .content {{
                padding: 30px;
            }}
            .note {{
                background-color: #e3f2fd;
                border-left: 4px solid #2196f3;
                padding: 15px;
                margin: 20px 0;
                border-radius: 0 5px 5px 0;
            }}
            .note h3 {{
                margin: 0 0 10px 0;
                color: #1976d2;
                font-size: 18px;
            }}
            .report-section {{
                margin: 40px 0;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                overflow: hidden;
            }}
            .report-header {{
                background-color: #282965;
                color: white;
                padding: 15px 20px;
                font-size: 20px;
                font-weight: 600;
            }}
            .report-info {{
                background-color: #f5f5f5;
                padding: 15px 20px;
                border-bottom: 1px solid #e0e0e0;
                font-size: 14px;
                color: #666;
            }}
            .summary-cards {{
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                padding: 20px;
                background-color: #fafafa;
            }}
            .summary-card {{
                flex: 1;
                min-width: 200px;
                background-color: white;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }}
            .summary-label {{
                font-size: 12px;
                color: #666;
                text-transform: uppercase;
                margin-bottom: 5px;
            }}
            .summary-value {{
                font-size: 20px;
                font-weight: 600;
                color: #282965;
            }}
            .table-container {{
                padding: 20px;
                overflow-x: auto;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 14px;
                margin: 0;
            }}
            th {{
                background-color: #282965;
                color: white;
                padding: 12px 8px;
                text-align: center;
                font-weight: 600;
                border: 1px solid #fff;
            }}
            td {{
                padding: 10px 8px;
                text-align: center;
                border: 1px solid #e0e0e0;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            tr:hover {{
                background-color: #f0f8ff;
            }}
            .total-row {{
                background-color: #ffe0b2 !important;
                font-weight: bold;
                border-top: 2px solid #282965;
            }}
            .footer {{
                background-color: #f5f5f5;
                padding: 20px;
                text-align: center;
                color: #666;
                font-size: 12px;
            }}
            .highlight-blue {{
                background-color: rgba(227, 242, 253, 0.5);
                font-weight: 500;
            }}
            .highlight-green {{
                background-color: rgba(200, 230, 201, 0.5);
                font-weight: 500;
            }}
            .highlight-orange {{
                background-color: rgba(255, 224, 178, 0.5);
                font-weight: 500;
            }}
            @media (max-width: 768px) {{
                .summary-cards {{
                    flex-direction: column;
                }}
                .summary-card {{
                    min-width: 100%;
                }}
                table {{
                    font-size: 12px;
                }}
                th, td {{
                    padding: 8px 4px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏢 YDC GÜNLÜK RAPOR</h1>
                <p>Tarih: {datetime.now().strftime('%d.%m.%Y %H:%M')}</p>
            </div>

            <div class="content">
    """

    # Not varsa ekle
    if note and note.strip():
        html_content += f"""
                <div class="note">
                    <h3>📋 Not</h3>
                    <p>{note}</p>
                </div>
        """

    # Rapor 1 - Muhasebe Grup Raporu
    if include_reports.get('report1', True) and 'report1' in report_data:
        report1 = report_data['report1']
        if 'error' not in report1:
            data = report1.get('data', [])
            summary = report1.get('summary', {})
            filters = report1.get('filters', {})

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📊 Malzeme Grubu Bazlı Özet Rapor
                    </div>
                    <div class="report-info">
                        Tarih: {filters.get('date', 'Belirtilmemiş')}
                    </div>

                    <div class="summary-cards">
                        <div class="summary-card">
                            <div class="summary-label">Toplam Brüt KG</div>
                            <div class="summary-value">{format_number(summary.get('total_brut_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Toplam Net KG</div>
                            <div class="summary-value">{format_number(summary.get('total_net_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Ortalama Brüt Fiyat</div>
                            <div class="summary-value">{format_number(summary.get('avg_brut_price', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Ortalama Net Fiyat</div>
                            <div class="summary-value">{format_number(summary.get('avg_net_price', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Toplam Tutar (TL)</div>
                            <div class="summary-value">{format_number(summary.get('total_tutar', 0))} ₺</div>
                        </div>
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>MUHASEBE GRUP İSMİ</th>
                                    <th>BRÜT KG</th>
                                    <th>BRÜT ORT. FİYAT (TL)</th>
                                    <th>NET KG</th>
                                    <th>NET ORT. FİYAT (TL)</th>
                                    <th>TUTAR (TL)</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            for item in data:
                html_content += f"""
                                <tr>
                                    <td style="text-align: left;">{item.get('muhasebe_grup_ismi', '')}</td>
                                    <td>{format_number(item.get('brut_kg', 0))}</td>
                                    <td>{format_number(item.get('brut_ort_fiyat', 0))} ₺</td>
                                    <td>{format_number(item.get('net_kg', 0))}</td>
                                    <td>{format_number(item.get('net_ort_fiyat', 0))} ₺</td>
                                    <td>{format_number(item.get('tutar_tl', 0))} ₺</td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                            <tfoot>
                                <tr class="total-row">
                                    <td style="text-align: left;"><strong>TOPLAM</strong></td>
                                    <td><strong>{format_number(summary.get('total_brut_kg', 0))}</strong></td>
                                    <td><strong>{format_number(summary.get('avg_brut_price', 0))} ₺</strong></td>
                                    <td><strong>{format_number(summary.get('total_net_kg', 0))}</strong></td>
                                    <td><strong>{format_number(summary.get('avg_net_price', 0))} ₺</strong></td>
                                    <td><strong>{format_number(summary.get('total_tutar', 0))} ₺</strong></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            """

    # Rapor 2 - Detaylı Satış Raporu - Yeni düzenleme ile
    if include_reports.get('report2', True) and 'report2' in report_data:
        report2 = report_data['report2']
        if 'error' not in report2:
            data = report2.get('data', [])
            filters = report2.get('filters', {})

            # Toplamları hesapla
            total_brut_kg = sum(item.get('brut_kg', 0) for item in data)
            total_net_kg = sum(item.get('net_kg', 0) for item in data)
            total_fire_kg = sum(item.get('fire_kg', 0) for item in data)
            total_hurda = sum(item.get('hurda', 0) for item in data)
            total_dovizli_tutar = sum(item.get('dovizli_tutar', 0) for item in data)
            total_tutar_tl = sum(item.get('tutar_tl', 0) for item in data)

            # Ortalama fiyatları hesapla
            avg_brut_fiyat_tl = total_tutar_tl / total_brut_kg if total_brut_kg > 0 else 0
            avg_net_fiyat_tl = total_tutar_tl / total_net_kg if total_net_kg > 0 else 0
            avg_brut_fiyat_doviz = total_dovizli_tutar / total_brut_kg if total_brut_kg > 0 and total_dovizli_tutar > 0 else 0
            avg_net_fiyat_doviz = total_dovizli_tutar / total_net_kg if total_net_kg > 0 and total_dovizli_tutar > 0 else 0

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📈 Malzeme Detaylı Satış Raporu
                    </div>
                    <div class="report-info">
                        Tarih: {filters.get('date', 'Belirtilmemiş')} | Toplam {len(data)} kayıt
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>CARİ</th>
                                    <th>SATIŞ ELEMANI</th>
                                    <th>MALZEME GRUP</th>
                                    <th>ÜRÜN ADI</th>
                                    <th>BRÜT KG</th>
                                    <th>NET KG</th>
                                    <th>FİRE KG</th>
                                    <th>HURDA</th>
                                    <th>BRÜT ORT. FİYAT (TL)</th>
                                    <th>NET ORT. FİYAT (TL)</th>
                                    <th>BRÜT ORT. FİYAT (DÖVİZ)</th>
                                    <th>NET ORT. FİYAT (DÖVİZ)</th>
                                    <th>DÖVİZ TÜRÜ</th>
                                    <th>DÖVİZLİ TUTAR</th>
                                    <th>TUTAR (TL)</th>
                                    <th>VADE</th>
                                    <th>TESLİM TARİHİ</th>
                                    <th>İRSALİYE TARİHİ</th>
                                    <th>TESLİM DURUM</th>
                                    <th>FATURALANMA DURUMU</th>
                                    <th>ÖDEME DURUMU</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            for item in data[:200]:  # İlk 200 kayıt (mail boyutunu sınırlamak için)
                html_content += f"""
                                <tr>
                                    <td style="text-align: left;">{item.get('cari', '')}</td>
                                    <td>{item.get('satis_elemani', '')}</td>
                                    <td>{item.get('malzeme_grup', '')}</td>
                                    <td style="text-align: left;">{item.get('urun_adi', '')}</td>
                                    <td class="highlight-blue">{format_number(item.get('brut_kg', 0))}</td>
                                    <td class="highlight-blue">{format_number(item.get('net_kg', 0))}</td>
                                    <td class="highlight-orange">{format_number(item.get('fire_kg', 0))}</td>
                                    <td class="highlight-orange">{format_number(item.get('hurda', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('brut_ort_fiyat_tl', 0))} ₺</td>
                                    <td class="highlight-green">{format_number(item.get('net_ort_fiyat_tl', 0))} ₺</td>
                                    <td class="highlight-green">{format_number(item.get('brut_ort_fiyat_doviz', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('net_ort_fiyat_doviz', 0))}</td>
                                    <td>{item.get('doviz', '')}</td>
                                    <td class="highlight-blue">{format_number(item.get('dovizli_tutar', 0))}</td>
                                    <td class="highlight-blue">{format_number(item.get('tutar_tl', 0))} ₺</td>
                                    <td>{item.get('vade', '')}</td>
                                    <td>{item.get('teslim_tarihi', '')}</td>
                                    <td>{item.get('irsaliye_tarihi', '')}</td>
                                    <td>{item.get('teslim_durum', '')}</td>
                                    <td>{item.get('fatura_durumu', '')}</td>
                                    <td>{item.get('odeme_durumu', '')}</td>
                                </tr>
                """

            if len(data) > 200:
                html_content += f"""
                                <tr>
                                    <td colspan="20" style="text-align: center; font-style: italic; color: #666;">
                                        ... ve {len(data) - 200} kayıt daha (Detaylar için sisteme giriş yapın)
                                    </td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                            <tfoot>
                                <tr class="total-row">
                                    <td colspan="4" style="text-align: left;"><strong>TOPLAM</strong></td>
                                    <td><strong>{format_number(total_brut_kg)}</strong></td>
                                    <td><strong>{format_number(total_net_kg)}</strong></td>
                                    <td><strong>{format_number(total_fire_kg)}</strong></td>
                                    <td><strong>{format_number(total_hurda)}</strong></td>
                                    <td><strong>{format_number(avg_brut_fiyat_tl)} ₺</strong></td>
                                    <td><strong>{format_number(avg_net_fiyat_tl)} ₺</strong></td>
                                    <td><strong>{format_number(avg_brut_fiyat_doviz)}</strong></td>
                                    <td><strong>{format_number(avg_net_fiyat_doviz)}</strong></td>
                                    <td></td>
                                    <td><strong>{format_number(total_dovizli_tutar)}</strong></td>
                                    <td><strong>{format_number(total_tutar_tl)} ₺</strong></td>
                                    <td colspan="6"></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            """

    # Rapor 3 - Günlük Hedef Raporu - Güncellenmiş özet kartları ile
    if include_reports.get('report3', True) and 'report3' in report_data:
        report3 = report_data['report3']
        if 'error' not in report3:
            data = report3.get('data', [])
            summary = report3.get('summary', {})
            filters = report3.get('filters', {})

            # Toplamları hesapla
            total_brut_kg = summary.get('total_brut_kg', 0)
            total_net_kg = summary.get('total_net_kg', 0)
            total_tutar = summary.get('total_tutar', 0)
            avg_brut_fiyat = total_tutar / total_brut_kg if total_brut_kg > 0 else 0
            avg_net_fiyat = total_tutar / total_net_kg if total_net_kg > 0 else 0

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📅 Günlük Hedef Tablo
                    </div>
                    <div class="report-info">
                        Ay: {filters.get('month', 'Belirtilmemiş')} | {filters.get('first_day', '')} - {filters.get('last_day', '')}
                    </div>

                    <div class="summary-cards">
                        <div class="summary-card">
                            <div class="summary-label">Günlük Ortalama Brüt KG</div>
                            <div class="summary-value">{format_number(summary.get('avg_daily_brut_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Günlük Ortalama Net KG</div>
                            <div class="summary-value">{format_number(summary.get('avg_daily_net_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Günlük Brüt Ort. Birim Fiyat</div>
                            <div class="summary-value">{format_number(summary.get('avg_daily_brut_price', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Günlük Net Ort. Birim Fiyat</div>
                            <div class="summary-value">{format_number(summary.get('avg_daily_net_price', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Günlük Ortalama Tutar</div>
                            <div class="summary-value">{format_number(summary.get('avg_daily_amount', 0))} ₺</div>
                        </div>
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>TARİH</th>
                                    <th>BRÜT KG</th>
                                    <th>BRÜT ORT. FİYAT (TL)</th>
                                    <th>NET KG</th>
                                    <th>NET ORT. FİYAT (TL)</th>
                                    <th>TUTAR (TL)</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            for item in data:
                html_content += f"""
                                <tr>
                                    <td>{item.get('tarih', '')}</td>
                                    <td class="highlight-blue">{format_number(item.get('brut_kg', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('brut_ort_fiyat', 0))} ₺</td>
                                    <td class="highlight-blue">{format_number(item.get('net_kg', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('net_ort_fiyat', 0))} ₺</td>
                                    <td class="highlight-orange">{format_number(item.get('tutar_tl', 0))} ₺</td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                            <tfoot>
                                <tr class="total-row">
                                    <td><strong>TOPLAM</strong></td>
                                    <td><strong>{format_number(total_brut_kg)}</strong></td>
                                    <td><strong>{format_number(avg_brut_fiyat)} ₺</strong></td>
                                    <td><strong>{format_number(total_net_kg)}</strong></td>
                                    <td><strong>{format_number(avg_net_fiyat)} ₺</strong></td>
                                    <td><strong>{format_number(total_tutar)} ₺</strong></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            """

    # Rapor 4 - Aylık Hedef Raporu - Güncellenmiş özet kartları ile
    if include_reports.get('report4', True) and 'report4' in report_data:
        report4 = report_data['report4']
        if 'error' not in report4:
            data = report4.get('data', [])
            summary = report4.get('summary', {})
            filters = report4.get('filters', {})

            # Toplamları hesapla
            total_brut_kg = summary.get('total_brut_kg', 0)
            total_net_kg = summary.get('total_net_kg', 0)
            total_tutar = summary.get('total_tutar', 0)
            avg_brut_fiyat = total_tutar / total_brut_kg if total_brut_kg > 0 else 0
            avg_net_fiyat = total_tutar / total_net_kg if total_net_kg > 0 else 0

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📆 Aylık Hedef Tablo
                    </div>
                    <div class="report-info">
                        Yıl: {filters.get('year', 'Belirtilmemiş')}
                    </div>

                    <div class="summary-cards">
                        <div class="summary-card">
                            <div class="summary-label">Aylık Ortalama Brüt KG</div>
                            <div class="summary-value">{format_number(summary.get('avg_monthly_brut_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Aylık Ortalama Net KG</div>
                            <div class="summary-value">{format_number(summary.get('avg_monthly_net_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Aylık Brüt Ort. Birim Fiyat</div>
                            <div class="summary-value">{format_number(summary.get('avg_monthly_brut_price', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Aylık Net Ort. Birim Fiyat</div>
                            <div class="summary-value">{format_number(summary.get('avg_monthly_net_price', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Aylık Ortalama Tutar</div>
                            <div class="summary-value">{format_number(summary.get('avg_monthly_amount', 0))} ₺</div>
                        </div>
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>AY</th>
                                    <th>BRÜT KG</th>
                                    <th>BRÜT ORT. FİYAT (TL)</th>
                                    <th>NET KG</th>
                                    <th>NET ORT. FİYAT (TL)</th>
                                    <th>TUTAR (TL)</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            for item in data:
                html_content += f"""
                                <tr>
                                    <td>{item.get('ay_name', '')}</td>
                                    <td class="highlight-blue">{format_number(item.get('brut_kg', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('brut_ort_fiyat', 0))} ₺</td>
                                    <td class="highlight-blue">{format_number(item.get('net_kg', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('net_ort_fiyat', 0))} ₺</td>
                                    <td class="highlight-orange">{format_number(item.get('tutar_tl', 0))} ₺</td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                            <tfoot>
                                <tr class="total-row">
                                    <td><strong>TOPLAM</strong></td>
                                    <td><strong>{format_number(total_brut_kg)}</strong></td>
                                    <td><strong>{format_number(avg_brut_fiyat)} ₺</strong></td>
                                    <td><strong>{format_number(total_net_kg)}</strong></td>
                                    <td><strong>{format_number(avg_net_fiyat)} ₺</strong></td>
                                    <td><strong>{format_number(total_tutar)} ₺</strong></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            """
    # Rapor 5 - Genel Analiz Raporu
    if include_reports.get('report5', False) and 'report5' in report_data:
        report5 = report_data['report5']
        if 'error' not in report5:
            filters = report5.get('filters', {})

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        🔍 Genel Analiz Raporu
                    </div>
                    <div class="report-info">
                        Yıl: {filters.get('year', 'Belirtilmemiş')} | Ay: {'Tüm Aylar' if filters.get('month') == '0' else f'Ay {filters.get("month", "")}'} 
                    </div>

                    <!-- En Çok Satış Yapılan Müşteriler - Tutar (TL) Bazlı -->
                    <div style="margin: 30px 0;">
                        <h3 style="color: #282965; border-bottom: 2px solid #282965; padding-bottom: 10px;">
                            👑 En Çok Satış Yapılan Müşteriler - Tutar (TL) Bazlı
                        </h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>SIRA</th>
                                        <th>CARİ</th>
                                        <th>NET KG</th>
                                        <th>TUTAR (TL)</th>
                                        <th>TOPLAM İÇİNDEKİ PAYI (%)</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            # Top Customers TL verilerini ekle
            customers_tl_data = report5.get('customers_tl', {}).get('data', [])
            for item in customers_tl_data[:15]:  # İlk 15 müşteriyi göster
                html_content += f"""
                                    <tr>
                                        <td>{item.get('sira', '')}</td>
                                        <td style="text-align: left;">{item.get('cari', '')}</td>
                                        <td>{format_number(item.get('net_kg', 0))}</td>
                                        <td>{format_number(item.get('tutar_tl', 0))} ₺</td>
                                        <td>{format_number(item.get('pay', 0), 1)}%</td>
                                    </tr>
                """

            customers_tl_summary = report5.get('customers_tl', {}).get('summary', {})
            html_content += f"""
                                </tbody>
                                <tfoot>
                                    <tr class="total-row">
                                        <td colspan="2"><strong>TOPLAM</strong></td>
                                        <td><strong>{format_number(customers_tl_summary.get('total_kg', 0))}</strong></td>
                                        <td><strong>{format_number(customers_tl_summary.get('total_amount', 0))} ₺</strong></td>
                                        <td><strong>100%</strong></td>
                                    </tr>
                                </tfoot>
                            </table>
                        </div>
                    </div>

                    <!-- En Çok Satış Yapılan Müşteriler - Net KG Bazlı -->
                    <div style="margin: 30px 0;">
                        <h3 style="color: #282965; border-bottom: 2px solid #282965; padding-bottom: 10px;">
                            ⚖️ En Çok Satış Yapılan Müşteriler - Net KG Bazlı
                        </h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>SIRA</th>
                                        <th>CARİ</th>
                                        <th>NET KG</th>
                                        <th>TUTAR (TL)</th>
                                        <th>TOPLAM İÇİNDEKİ PAYI (%)</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            # Top Customers KG verilerini ekle
            customers_kg_data = report5.get('customers_kg', {}).get('data', [])
            for item in customers_kg_data[:15]:  # İlk 15 müşteriyi göster
                html_content += f"""
                                    <tr>
                                        <td>{item.get('sira', '')}</td>
                                        <td style="text-align: left;">{item.get('cari', '')}</td>
                                        <td>{format_number(item.get('net_kg', 0))}</td>
                                        <td>{format_number(item.get('tutar_tl', 0))} ₺</td>
                                        <td>{format_number(item.get('pay', 0), 1)}%</td>
                                    </tr>
                """

            customers_kg_summary = report5.get('customers_kg', {}).get('summary', {})
            html_content += f"""
                                </tbody>
                                <tfoot>
                                    <tr class="total-row">
                                        <td colspan="2"><strong>TOPLAM</strong></td>
                                        <td><strong>{format_number(customers_kg_summary.get('total_kg', 0))}</strong></td>
                                        <td><strong>{format_number(customers_kg_summary.get('total_amount', 0))} ₺</strong></td>
                                        <td><strong>100%</strong></td>
                                    </tr>
                                </tfoot>
                            </table>
                        </div>
                    </div>

                    <!-- En Çok Satılan Malzeme Grupları - Tutar (TL) -->
                    <div style="margin: 30px 0;">
                        <h3 style="color: #282965; border-bottom: 2px solid #282965; padding-bottom: 10px;">
                            📦 En Çok Satılan Malzeme Grupları - Tutar (TL)
                        </h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>SIRA</th>
                                        <th>MALZEME GRUP</th>
                                        <th>TUTAR (TL)</th>
                                        <th>PAY (%)</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            # Top Material Groups TL verilerini ekle
            material_groups_tl_data = report5.get('material_groups_tl', {}).get('data', [])
            for item in material_groups_tl_data[:10]:  # İlk 10 malzeme grubunu göster
                html_content += f"""
                                    <tr>
                                        <td>{item.get('sira', '')}</td>
                                        <td style="text-align: left;">{item.get('malzeme_grup', '')}</td>
                                        <td>{format_number(item.get('tutar_tl', 0))} ₺</td>
                                        <td>{format_number(item.get('pay', 0), 1)}%</td>
                                    </tr>
                """

            html_content += """
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Aylık Satış Trendi -->
                    <div style="margin: 30px 0;">
                        <h3 style="color: #282965; border-bottom: 2px solid #282965; padding-bottom: 10px;">
                            📈 Aylık Satış Trendi
                        </h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>AY</th>
                                        <th>BRÜT KG</th>
                                        <th>NET KG</th>
                                        <th>TUTAR (TL)</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            # Monthly Trend verilerini ekle
            monthly_trend_data = report5.get('monthly_trend', {}).get('data', [])
            total_trend_brut = 0
            total_trend_net = 0
            total_trend_tutar = 0

            for item in monthly_trend_data:
                brut_kg = item.get('brut_kg', 0)
                net_kg = item.get('net_kg', 0)
                tutar_tl = item.get('tutar_tl', 0)

                total_trend_brut += brut_kg
                total_trend_net += net_kg
                total_trend_tutar += tutar_tl

                html_content += f"""
                                    <tr>
                                        <td>{item.get('ay_name', '')}</td>
                                        <td>{format_number(brut_kg)}</td>
                                        <td>{format_number(net_kg)}</td>
                                        <td>{format_number(tutar_tl)} ₺</td>
                                    </tr>
                """

            html_content += f"""
                                </tbody>
                                <tfoot>
                                    <tr class="total-row">
                                        <td><strong>TOPLAM</strong></td>
                                        <td><strong>{format_number(total_trend_brut)}</strong></td>
                                        <td><strong>{format_number(total_trend_net)}</strong></td>
                                        <td><strong>{format_number(total_trend_tutar)} ₺</strong></td>
                                    </tr>
                                </tfoot>
                            </table>
                        </div>
                    </div>
                </div>
            """

        # Footer (bu kısım da eksikti)
        html_content += """
                </div>

                <div class="footer">
                    <p>Bu rapor BYT Digital tarafından otomatik olarak oluşturulmuştur.</p>
                    <p>Rapor Tarihi: """ + datetime.now().strftime('%d.%m.%Y %H:%M') + """ | © """ + str(
            datetime.now().year) + """ BYT DIGITAL</p>
                </div>
            </div>
        </body>
        </html>
        """

        return html_content
    # Footer
    html_content += f"""
            </div>

            <div class="footer">
                <p>Bu rapor BYT Digital tarafından otomatik olarak oluşturulmuştur.</p>
                <p>Rapor Tarihi: {datetime.now().strftime('%d.%m.%Y %H:%M')} | © {datetime.now().year} BYT DIGITAL</p>
            </div>
        </div>
    </body>
    </html>
    """

    return html_content


# YAĞCILAR Genel Satış Raporu sayfası için ana rota
@app.route('/yagcilar-genel-satis-raporu')
@login_required
@permission_required(menu_id=1025, permission_type='view')  # Menü ID'nizi uygun şekilde değiştirin
def yagcilar_genel_satis_raporu():
    """YAĞCILAR Genel Satış Raporu sayfasını render eder."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    return render_template('yagcilar_genel_satis_raporu.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions)


# Filtre seçeneklerini getiren API
@app.route('/yagcilar-genel-satis-raporu/filter-options', methods=['GET'])
@login_required
def yagcilar_genel_satis_raporu_filter_options():
    """Rapor filtreleri için seçenekleri döndürür."""
    try:
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()

        # Cari listesi
        cursor.execute("""
            SELECT DISTINCT CARI
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE CARI IS NOT NULL
            ORDER BY CARI
        """)
        cari_list = [row[0] for row in cursor.fetchall()]

        # Malzeme grup listesi
        cursor.execute("""
            SELECT DISTINCT [Malzeme Grup Kodu] AS MalzemeGrup
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [Malzeme Grup Kodu] IS NOT NULL
            ORDER BY [Malzeme Grup Kodu]
        """)
        malzeme_grup_list = [row[0] for row in cursor.fetchall()]

        # Satış elemanı listesi
        cursor.execute("""
            SELECT DISTINCT [SATIŞ ELEMANI] AS SatisElemani
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [SATIŞ ELEMANI] IS NOT NULL
            ORDER BY [SATIŞ ELEMANI]
        """)
        satis_elemani_list = [row[0] for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'cari_list': cari_list,
            'malzeme_grup_list': malzeme_grup_list,
            'satis_elemani_list': satis_elemani_list
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 1 verilerini getiren API - Malzeme Grup Raporu
@app.route('/yagcilar-genel-satis-raporu/report1-data', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_report1_data():
    """Malzeme Grup Raporu verilerini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        date_str = request.form.get('date', '')
        month_str = request.form.get('month', '')
        cari_list = request.form.getlist('cari[]') or []
        malzeme_grup_list = request.form.getlist('malzeme_grup[]') or []
        satis_elemani_list = request.form.getlist('satis_elemani[]') or []

        # SQL sorgusu için temel koşulları hazırla
        sql_conditions = []
        params = []

        # Tarih veya ay filtresini ekle
        if date_str:
            try:
                selected_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%Y-%m-%d')
                sql_conditions.append("CONVERT(DATE, [TARIH]) = ?")
                params.append(selected_date)
            except ValueError:
                pass
        elif month_str:
            try:
                year, month = map(int, month_str.split('-'))
                sql_conditions.append("[YIL] = ? AND [AY] = ?")
                params.extend([year, month])
            except (ValueError, IndexError):
                pass

        # Diğer filtreleri ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_conditions.append(f"[CARI] IN ({placeholders})")
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_conditions.append(f"[Malzeme Grup Kodu] IN ({placeholders})")
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_conditions.append(f"[SATIŞ ELEMANI] IN ({placeholders})")
            params.extend(satis_elemani_list)

        # SQL WHERE koşulunu oluştur
        where_clause = " AND ".join(sql_conditions) if sql_conditions else "1=1"

        # SQL sorgusu oluştur
        sql_query = f"""
            SELECT 
                [Malzeme Grup Kodu] AS MalzemeGrupKodu,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE {where_clause}
            GROUP BY [Malzeme Grup Kodu] 
            ORDER BY SUM([TUTAR]) DESC
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            malzeme_grup = row[0] or "Belirtilmemiş"
            net_kg = float(row[1]) if row[1] else 0
            tutar = float(row[2]) if row[2] else 0

            # Toplam değerleri hesapla
            total_net_kg += net_kg
            total_tutar += tutar

            # Birim fiyatları hesapla
            net_ort_fiyat_tl = tutar / net_kg if net_kg > 0 else 0

            result.append({
                'malzeme_grup_kodu': malzeme_grup,
                'net_kg': net_kg,
                'tutar_tl': tutar,
                'net_ort_fiyat_tl': net_ort_fiyat_tl
            })

        cursor.close()
        conn.close()

        # Genel toplam değerlerini hesapla
        avg_net_price_tl = total_tutar / total_net_kg if total_net_kg > 0 else 0

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar,
                'avg_net_price_tl': avg_net_price_tl
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 2 verilerini getiren API - Detaylı Satış Raporu
@app.route('/yagcilar-genel-satis-raporu/report2-data', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_report2_data():
    """Detaylı Satış Raporu verilerini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        date_str = request.form.get('date', '')
        month_str = request.form.get('month', '')
        cari_list = request.form.getlist('cari[]') or []
        malzeme_grup_list = request.form.getlist('malzeme_grup[]') or []
        satis_elemani_list = request.form.getlist('satis_elemani[]') or []

        # SQL sorgusu için temel koşulları hazırla
        sql_conditions = []
        params = []

        # Tarih veya ay filtresini ekle
        if date_str:
            try:
                selected_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%Y-%m-%d')
                sql_conditions.append("CONVERT(DATE, [TARIH]) = ?")
                params.append(selected_date)
            except ValueError:
                pass
        elif month_str:
            try:
                year, month = map(int, month_str.split('-'))
                sql_conditions.append("[YIL] = ? AND [AY] = ?")
                params.extend([year, month])
            except (ValueError, IndexError):
                pass

        # Diğer filtreleri ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_conditions.append(f"[CARI] IN ({placeholders})")
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_conditions.append(f"[Malzeme Grup Kodu] IN ({placeholders})")
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_conditions.append(f"[SATIŞ ELEMANI] IN ({placeholders})")
            params.extend(satis_elemani_list)

        # SQL WHERE koşulunu oluştur
        where_clause = " AND ".join(sql_conditions) if sql_conditions else "1=1"

        # SQL sorgusu oluştur
        sql_query = f"""
            SELECT 
                [CARI],
                [SATIŞ ELEMANI],
                [Malzeme Grup Kodu],
                [URUN_HIZMET_AD],
                [ACIKLAMA],
                [NET_KG],
                [Döviz Türü],
                [DOVIZ_TOPLAM],
                [TUTAR],
                [ÖDEME TİPİ],
                CONVERT(VARCHAR(10), [TESLİM TARİHİ], 103) AS TeslimTarihi
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE {where_clause}
            ORDER BY [CARI], [URUN_HIZMET_AD]
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []

        for row in cursor.fetchall():
            cari = row[0] or ""
            satis_elemani = row[1] or ""
            malzeme_grup = row[2] or ""
            urun_adi = row[3] or ""
            aciklama = row[4] or ""
            net_kg = float(row[5]) if row[5] else 0
            doviz_turu = row[6] or "TL"
            doviz_toplam = float(row[7]) if row[7] else 0
            tutar_tl = float(row[8]) if row[8] else 0
            odeme_tipi = row[9] or ""
            teslim_tarihi = row[10] or ""

            result.append({
                'cari': cari,
                'satis_elemani': satis_elemani,
                'malzeme_grup': malzeme_grup,
                'urun_adi': urun_adi,
                'aciklama': aciklama,
                'net_kg': net_kg,
                'doviz_turu': doviz_turu,
                'doviz_toplam': doviz_toplam,
                'tutar_tl': tutar_tl,
                'odeme_tipi': odeme_tipi,
                'teslim_tarihi': teslim_tarihi
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 3 verilerini getiren API - Günlük Hedef Raporu
@app.route('/yagcilar-genel-satis-raporu/report3-data', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_report3_data():
    """Günlük Hedef Raporu verilerini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        month_str = request.form.get('month', '')
        cari_list = request.form.getlist('cari[]') or []
        malzeme_grup_list = request.form.getlist('malzeme_grup[]') or []
        satis_elemani_list = request.form.getlist('satis_elemani[]') or []

        # Ay formatını kontrol et
        if month_str:
            try:
                # Ay formatı: YYYY-MM
                year, month = map(int, month_str.split('-'))
                first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
                # Ayın son gününü bul
                _, last_day_of_month = calendar.monthrange(year, month)
                last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')
            except (ValueError, IndexError):
                now = datetime.now()
                year, month = now.year, now.month
                first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
                _, last_day_of_month = calendar.monthrange(year, month)
                last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')
        else:
            now = datetime.now()
            year, month = now.year, now.month
            first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
            _, last_day_of_month = calendar.monthrange(year, month)
            last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                CONVERT(VARCHAR(10), [TARIH], 103) AS Tarih,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE CONVERT(DATE, [TARIH]) BETWEEN ? AND ?
        """

        params = [first_day, last_day]

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [TARIH] ORDER BY [TARIH]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            tarih = row[0] or ""
            net_kg = float(row[1]) if row[1] else 0
            tutar_tl = float(row[2]) if row[2] else 0

            # Toplam değerler
            total_net_kg += net_kg
            total_tutar += tutar_tl

            # Birim fiyatları hesapla
            net_ort_fiyat_tl = tutar_tl / net_kg if net_kg > 0 else 0

            result.append({
                'tarih': tarih,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl,
                'net_ort_fiyat_tl': net_ort_fiyat_tl
            })

        cursor.close()
        conn.close()

        # Günlük ortalamalar hesapla
        day_count = len(result) if result else 1
        avg_daily_net_kg = total_net_kg / day_count
        avg_daily_net_price_tl = total_tutar / total_net_kg if total_net_kg > 0 else 0
        avg_daily_amount_tl = total_tutar / day_count

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'avg_daily_net_kg': avg_daily_net_kg,
                'avg_daily_net_price_tl': avg_daily_net_price_tl,
                'avg_daily_amount_tl': avg_daily_amount_tl,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 4 verilerini getiren API - Aylık Hedef Raporu
@app.route('/yagcilar-genel-satis-raporu/report4-data', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_report4_data():
    """Aylık Hedef Raporu verilerini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')
        cari_list = request.form.getlist('cari[]') or []
        malzeme_grup_list = request.form.getlist('malzeme_grup[]') or []
        satis_elemani_list = request.form.getlist('satis_elemani[]') or []

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [AY],
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
        """

        params = [year]

        # Filtre koşulları ekle
        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [AY] ORDER BY [AY]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Ay isimlerini hazırla
        ay_isimleri = [
            "OCAK", "ŞUBAT", "MART", "NİSAN", "MAYIS", "HAZİRAN",
            "TEMMUZ", "AĞUSTOS", "EYLÜL", "EKİM", "KASIM", "ARALIK"
        ]

        # Sonuçları al ve işle
        result = []
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            ay_no = int(row[0]) if row[0] else 0
            ay_name = ay_isimleri[ay_no - 1] if 1 <= ay_no <= 12 else f"Ay {ay_no}"
            net_kg = float(row[1]) if row[1] else 0
            tutar_tl = float(row[2]) if row[2] else 0

            # Toplam değerler
            total_net_kg += net_kg
            total_tutar += tutar_tl

            # Birim fiyatları hesapla
            net_ort_fiyat_tl = tutar_tl / net_kg if net_kg > 0 else 0

            result.append({
                'ay': str(ay_no),
                'ay_name': ay_name,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl,
                'net_ort_fiyat_tl': net_ort_fiyat_tl
            })

        cursor.close()
        conn.close()

        # Aylık ortalamalar hesapla
        month_count = len(result) if result else 1
        avg_monthly_net_kg = total_net_kg / month_count
        avg_monthly_net_price_tl = total_tutar / total_net_kg if total_net_kg > 0 else 0
        avg_monthly_amount_tl = total_tutar / month_count

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'avg_monthly_net_kg': avg_monthly_net_kg,
                'avg_monthly_net_price_tl': avg_monthly_net_price_tl,
                'avg_monthly_amount_tl': avg_monthly_amount_tl,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Rapor 5 - Genel Analiz Raporu APIs

# Top Customers by TL
@app.route('/yagcilar-genel-satis-raporu/top-customers-by-tl', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_top_customers_by_tl():
    """Tutar (TL) bazında en çok satış yapılan müşterileri döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [CARI],
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
        """

        params = [year]

        # Ay filtresi ekle
        if month_str != '0':
            try:
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)
            except ValueError:
                pass

        sql_query += """
            GROUP BY [CARI]
            ORDER BY SUM([TUTAR]) DESC
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_kg = 0
        total_amount = 0

        # Önce tüm verileri topla
        all_data = []
        for row in cursor.fetchall():
            cari = row[0] or "Belirtilmemiş"
            net_kg = float(row[1]) if row[1] else 0
            tutar_tl = float(row[2]) if row[2] else 0

            all_data.append({
                'cari': cari,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl
            })

            total_kg += net_kg
            total_amount += tutar_tl

        # İlk top_count kadar veriyi dön
        for item in all_data[:top_count]:
            # Pay yüzdesini hesapla
            pay = (item['tutar_tl'] / total_amount * 100) if total_amount > 0 else 0

            result.append({
                'cari': item['cari'],
                'net_kg': item['net_kg'],
                'tutar_tl': item['tutar_tl'],
                'pay': pay
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'total_kg': total_kg,
                'total_amount': total_amount
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Top Customers by KG
@app.route('/yagcilar-genel-satis-raporu/top-customers-by-kg', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_top_customers_by_kg():
    """Net KG bazında en çok satış yapılan müşterileri döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [CARI],
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
        """

        params = [year]

        # Ay filtresi ekle
        if month_str != '0':
            try:
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)
            except ValueError:
                pass

        sql_query += """
            GROUP BY [CARI]
            ORDER BY SUM([NET_KG]) DESC
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_kg = 0
        total_amount = 0

        # Önce tüm verileri topla
        all_data = []
        for row in cursor.fetchall():
            cari = row[0] or "Belirtilmemiş"
            net_kg = float(row[1]) if row[1] else 0
            tutar_tl = float(row[2]) if row[2] else 0

            all_data.append({
                'cari': cari,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl
            })

            total_kg += net_kg
            total_amount += tutar_tl

        # İlk top_count kadar veriyi dön
        for item in all_data[:top_count]:
            # Pay yüzdesini hesapla
            pay = (item['net_kg'] / total_kg * 100) if total_kg > 0 else 0

            result.append({
                'cari': item['cari'],
                'net_kg': item['net_kg'],
                'tutar_tl': item['tutar_tl'],
                'pay': pay
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result,
            'summary': {
                'total_kg': total_kg,
                'total_amount': total_amount
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Top Material Groups by TL
@app.route('/yagcilar-genel-satis-raporu/top-material-groups-by-tl', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_top_material_groups_by_tl():
    """Tutar (TL) bazında en çok satılan malzeme gruplarını döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [Malzeme Grup Kodu],
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
        """

        params = [year]

        # Ay filtresi ekle
        if month_str != '0':
            try:
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)
            except ValueError:
                pass

        sql_query += """
            GROUP BY [Malzeme Grup Kodu]
            ORDER BY SUM([TUTAR]) DESC
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_amount = 0

        # Önce tüm verileri topla
        all_data = []
        for row in cursor.fetchall():
            malzeme_grup = row[0] or "Belirtilmemiş"
            tutar_tl = float(row[1]) if row[1] else 0

            all_data.append({
                'malzeme_grup': malzeme_grup,
                'tutar_tl': tutar_tl
            })

            total_amount += tutar_tl

        # İlk top_count kadar veriyi dön
        for item in all_data[:top_count]:
            # Pay yüzdesini hesapla
            pay = (item['tutar_tl'] / total_amount * 100) if total_amount > 0 else 0

            result.append({
                'malzeme_grup': item['malzeme_grup'],
                'tutar_tl': item['tutar_tl'],
                'pay': pay
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Top Material Groups by KG
@app.route('/yagcilar-genel-satis-raporu/top-material-groups-by-kg', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_top_material_groups_by_kg():
    """Net KG bazında en çok satılan malzeme gruplarını döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [Malzeme Grup Kodu],
                SUM([NET_KG]) AS NetKg
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
        """

        params = [year]

        # Ay filtresi ekle
        if month_str != '0':
            try:
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)
            except ValueError:
                pass

        sql_query += """
            GROUP BY [Malzeme Grup Kodu]
            ORDER BY SUM([NET_KG]) DESC
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_kg = 0

        # Önce tüm verileri topla
        all_data = []
        for row in cursor.fetchall():
            malzeme_grup = row[0] or "Belirtilmemiş"
            net_kg = float(row[1]) if row[1] else 0

            all_data.append({
                'malzeme_grup': malzeme_grup,
                'net_kg': net_kg
            })

            total_kg += net_kg

        # İlk top_count kadar veriyi dön
        for item in all_data[:top_count]:
            # Pay yüzdesini hesapla
            pay = (item['net_kg'] / total_kg * 100) if total_kg > 0 else 0

            result.append({
                'malzeme_grup': item['malzeme_grup'],
                'net_kg': item['net_kg'],
                'pay': pay
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Top Products by TL
@app.route('/yagcilar-genel-satis-raporu/top-products-by-tl', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_top_products_by_tl():
    """Tutar (TL) bazında en çok satılan ürünleri döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [URUN_HIZMET_AD],
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
        """

        params = [year]

        # Ay filtresi ekle
        if month_str != '0':
            try:
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)
            except ValueError:
                pass

        sql_query += """
            GROUP BY [URUN_HIZMET_AD]
            ORDER BY SUM([TUTAR]) DESC
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_amount = 0

        # Önce tüm verileri topla
        all_data = []
        for row in cursor.fetchall():
            urun_adi = row[0] or "Belirtilmemiş"
            tutar_tl = float(row[1]) if row[1] else 0

            all_data.append({
                'urun_adi': urun_adi,
                'tutar_tl': tutar_tl
            })

            total_amount += tutar_tl

        # İlk top_count kadar veriyi dön
        for item in all_data[:top_count]:
            # Pay yüzdesini hesapla
            pay = (item['tutar_tl'] / total_amount * 100) if total_amount > 0 else 0

            result.append({
                'urun_adi': item['urun_adi'],
                'tutar_tl': item['tutar_tl'],
                'pay': pay
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Top Products by KG
@app.route('/yagcilar-genel-satis-raporu/top-products-by-kg', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_top_products_by_kg():
    """Net KG bazında en çok satılan ürünleri döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')
        month_str = request.form.get('month', '0')
        top_count = int(request.form.get('top_count', '20'))

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [URUN_HIZMET_AD],
                SUM([NET_KG]) AS NetKg
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
        """

        params = [year]

        # Ay filtresi ekle
        if month_str != '0':
            try:
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)
            except ValueError:
                pass

        sql_query += """
            GROUP BY [URUN_HIZMET_AD]
            ORDER BY SUM([NET_KG]) DESC
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Sonuçları al ve işle
        result = []
        total_kg = 0

        # Önce tüm verileri topla
        all_data = []
        for row in cursor.fetchall():
            urun_adi = row[0] or "Belirtilmemiş"
            net_kg = float(row[1]) if row[1] else 0

            all_data.append({
                'urun_adi': urun_adi,
                'net_kg': net_kg
            })

            total_kg += net_kg

        # İlk top_count kadar veriyi dön
        for item in all_data[:top_count]:
            # Pay yüzdesini hesapla
            pay = (item['net_kg'] / total_kg * 100) if total_kg > 0 else 0

            result.append({
                'urun_adi': item['urun_adi'],
                'net_kg': item['net_kg'],
                'pay': pay
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# Monthly Sales Trend
@app.route('/yagcilar-genel-satis-raporu/monthly-sales-trend', methods=['POST'])
@login_required
def yagcilar_genel_satis_raporu_monthly_sales_trend():
    """Aylık satış trendini döndürür."""
    try:
        # Formdan gelen filtre değerlerini al
        year_str = request.form.get('year', '')

        # Yıl formatını kontrol et
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [AY],
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
            GROUP BY [AY]
            ORDER BY [AY]
        """

        params = [year]

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()  # TIGERDB bağlantısı
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Ay isimlerini hazırla
        ay_isimleri = [
            "OCAK", "ŞUBAT", "MART", "NİSAN", "MAYIS", "HAZİRAN",
            "TEMMUZ", "AĞUSTOS", "EYLÜL", "EKİM", "KASIM", "ARALIK"
        ]

        # Sonuçları al ve işle
        result = []
        for row in cursor.fetchall():
            ay_no = int(row[0]) if row[0] else 0
            ay_name = ay_isimleri[ay_no - 1] if 1 <= ay_no <= 12 else f"Ay {ay_no}"
            net_kg = float(row[1]) if row[1] else 0
            tutar_tl = float(row[2]) if row[2] else 0

            result.append({
                'ay': str(ay_no),
                'ay_name': ay_name,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl
            })

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


# 4. Yağcılar Genel Satış Raporu Mail Gönderme (paste-4.txt'den)
@app.route('/yagcilar-genel-satis-raporu/send-mail', methods=['POST'])
@login_required
@permission_required(menu_id=1025, permission_type='view')
def yagcilar_genel_satis_raporu_send_mail():
    """Tüm raporları HTML formatında mail olarak gönderir."""
    try:
        # JSON verisini al
        mail_data = request.get_json()

        if not mail_data:
            return jsonify({
                'success': False,
                'error': 'Mail verisi alınamadı'
            })

        # Gmail SMTP ayarları
        sender_email = "yagcilarholding1@gmail.com"
        sender_password = "bqnp sius nztz padc"
        recipients = []

        # Alıcı listesini hazırla
        if isinstance(mail_data.get('recipients'), list):
            recipients = [email.strip() for email in mail_data['recipients'] if email.strip()]
        else:
            recipients = ["dogukanturan@ydcmetal.com.tr", "bayramyagci@yagcilar.com.tr"]

        if not recipients:
            return jsonify({
                'success': False,
                'error': 'Geçerli alıcı e-posta adresi bulunamadı'
            })

        # E-posta konteyneri oluştur
        msg = MIMEMultipart('alternative')
        msg['Subject'] = mail_data.get('subject', 'YAĞCILAR Genel Satış Rapor')
        msg['From'] = sender_email
        msg['To'] = ', '.join(recipients)

        # Rapor verilerini topla
        report_data = {}
        include_reports = mail_data.get('include_reports', {})
        filters = mail_data.get('filters', {})

        # Rapor 1 - Malzeme Grup Raporu
        if include_reports.get('report1', True):
            report_data['report1'] = get_yagcilar_report1_data_for_mail(filters.get('report1', {}))

        # Rapor 2 - Detaylı Satış Raporu
        if include_reports.get('report2', True):
            report_data['report2'] = get_yagcilar_report2_data_for_mail(filters.get('report2', {}))

        # Rapor 3 - Günlük Hedef Raporu
        if include_reports.get('report3', True):
            report_data['report3'] = get_yagcilar_report3_data_for_mail(filters.get('report3', {}))

        # Rapor 4 - Aylık Hedef Raporu
        if include_reports.get('report4', True):
            report_data['report4'] = get_yagcilar_report4_data_for_mail(filters.get('report4', {}))

        # Rapor 5 - Genel Analiz Raporu
        if include_reports.get('report5', False):
            report_data['report5'] = get_yagcilar_report5_data_for_mail(
                filters.get('report5', {'year': datetime.now().year, 'month': '0', 'top_count': 20}))

        # HTML mail içeriğini oluştur
        html_content = generate_yagcilar_mail_html(report_data, mail_data.get('note', ''), include_reports)

        # HTML içeriği ekle
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(html_part)

        # Gmail SMTP ile mail gönder
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Gmail için TLS gerekli
        server.login(sender_email, sender_password)

        for recipient in recipients:
            server.sendmail(sender_email, recipient, msg.as_string())

        server.quit()

        return jsonify({
            'success': True,
            'message': f'Mail başarıyla {len(recipients)} alıcıya gönderildi'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Mail gönderilirken hata oluştu: {str(e)}'
        })


def get_yagcilar_report1_data_for_mail(filters):
    """Mail için Rapor 1 verilerini getirir"""
    try:
        # SQL sorgusu için temel koşulları hazırla
        sql_conditions = []
        params = []

        # Tarih veya ay filtresini ekle
        date_str = filters.get('date', '')
        month_str = filters.get('month', '')

        if date_str:
            try:
                selected_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%Y-%m-%d')
                sql_conditions.append("CONVERT(DATE, [TARIH]) = ?")
                params.append(selected_date)
            except ValueError:
                pass
        elif month_str:
            try:
                year, month = map(int, month_str.split('-'))
                sql_conditions.append("[YIL] = ? AND [AY] = ?")
                params.extend([year, month])
            except (ValueError, IndexError):
                pass

        # Diğer filtreleri ekle
        cari_list = filters.get('cari', [])
        malzeme_grup_list = filters.get('malzeme_grup', [])
        satis_elemani_list = filters.get('satis_elemani', [])

        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_conditions.append(f"[CARI] IN ({placeholders})")
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_conditions.append(f"[Malzeme Grup Kodu] IN ({placeholders})")
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_conditions.append(f"[SATIŞ ELEMANI] IN ({placeholders})")
            params.extend(satis_elemani_list)

        # SQL WHERE koşulunu oluştur
        where_clause = " AND ".join(sql_conditions) if sql_conditions else "1=1"

        # SQL sorgusu oluştur
        sql_query = f"""
            SELECT 
                [Malzeme Grup Kodu] AS MalzemeGrupKodu,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE {where_clause}
            GROUP BY [Malzeme Grup Kodu] 
            ORDER BY SUM([TUTAR]) DESC
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        result = []
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            malzeme_grup = row[0] or "Belirtilmemiş"
            net_kg = float(row[1]) if row[1] else 0
            tutar = float(row[2]) if row[2] else 0

            total_net_kg += net_kg
            total_tutar += tutar

            net_ort_fiyat_tl = tutar / net_kg if net_kg > 0 else 0

            result.append({
                'malzeme_grup_kodu': malzeme_grup,
                'net_kg': net_kg,
                'tutar_tl': tutar,
                'net_ort_fiyat_tl': net_ort_fiyat_tl
            })

        cursor.close()
        conn.close()

        avg_net_price_tl = total_tutar / total_net_kg if total_net_kg > 0 else 0

        return {
            'data': result,
            'summary': {
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar,
                'avg_net_price_tl': avg_net_price_tl
            },
            'filters': filters
        }

    except Exception as e:
        return {'error': str(e)}


def get_yagcilar_report2_data_for_mail(filters):
    """Mail için Rapor 2 verilerini getirir"""
    try:
        # SQL sorgusu için temel koşulları hazırla
        sql_conditions = []
        params = []

        # Tarih veya ay filtresini ekle
        date_str = filters.get('date', '')
        month_str = filters.get('month', '')

        if date_str:
            try:
                selected_date = datetime.strptime(date_str, '%Y-%m-%d').strftime('%Y-%m-%d')
                sql_conditions.append("CONVERT(DATE, [TARIH]) = ?")
                params.append(selected_date)
            except ValueError:
                pass
        elif month_str:
            try:
                year, month = map(int, month_str.split('-'))
                sql_conditions.append("[YIL] = ? AND [AY] = ?")
                params.extend([year, month])
            except (ValueError, IndexError):
                pass

        # Diğer filtreleri ekle
        cari_list = filters.get('cari', [])
        malzeme_grup_list = filters.get('malzeme_grup', [])
        satis_elemani_list = filters.get('satis_elemani', [])

        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_conditions.append(f"[CARI] IN ({placeholders})")
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_conditions.append(f"[Malzeme Grup Kodu] IN ({placeholders})")
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_conditions.append(f"[SATIŞ ELEMANI] IN ({placeholders})")
            params.extend(satis_elemani_list)

        # SQL WHERE koşulunu oluştur
        where_clause = " AND ".join(sql_conditions) if sql_conditions else "1=1"

        # SQL sorgusu oluştur
        sql_query = f"""
            SELECT 
                [CARI],
                [SATIŞ ELEMANI],
                [Malzeme Grup Kodu],
                [URUN_HIZMET_AD],
                [ACIKLAMA],
                [NET_KG],
                [Döviz Türü],
                [DOVIZ_TOPLAM],
                [TUTAR],
                [ÖDEME TİPİ],
                CONVERT(VARCHAR(10), [TESLİM TARİHİ], 103) AS TeslimTarihi
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE {where_clause}
            ORDER BY [CARI], [URUN_HIZMET_AD]
        """

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        result = []
        total_net_kg = 0
        total_doviz_toplam = 0
        total_tutar_tl = 0

        for row in cursor.fetchall():
            cari = row[0] or ""
            satis_elemani = row[1] or ""
            malzeme_grup = row[2] or ""
            urun_adi = row[3] or ""
            aciklama = row[4] or ""
            net_kg = float(row[5]) if row[5] else 0
            doviz_turu = row[6] or "TL"
            doviz_toplam = float(row[7]) if row[7] else 0
            tutar_tl = float(row[8]) if row[8] else 0
            odeme_tipi = row[9] or ""
            teslim_tarihi = row[10] or ""

            # Net ortalama fiyatları hesapla
            net_ort_fiyat_tl = tutar_tl / net_kg if net_kg > 0 else 0
            net_ort_fiyat_doviz = doviz_toplam / net_kg if net_kg > 0 and doviz_toplam > 0 else 0

            # Toplamları güncelle
            total_net_kg += net_kg
            total_doviz_toplam += doviz_toplam
            total_tutar_tl += tutar_tl

            result.append({
                'cari': cari,
                'satis_elemani': satis_elemani,
                'malzeme_grup': malzeme_grup,
                'urun_adi': urun_adi,
                'aciklama': aciklama,
                'net_kg': net_kg,
                'net_ort_fiyat_tl': net_ort_fiyat_tl,
                'net_ort_fiyat_doviz': net_ort_fiyat_doviz,
                'doviz_turu': doviz_turu,
                'doviz_toplam': doviz_toplam,
                'tutar_tl': tutar_tl,
                'odeme_tipi': odeme_tipi,
                'teslim_tarihi': teslim_tarihi
            })

        cursor.close()
        conn.close()

        # Ortalama fiyatları hesapla
        avg_net_fiyat_tl = total_tutar_tl / total_net_kg if total_net_kg > 0 else 0
        avg_net_fiyat_doviz = total_doviz_toplam / total_net_kg if total_net_kg > 0 and total_doviz_toplam > 0 else 0

        return {
            'data': result,
            'summary': {
                'total_net_kg': total_net_kg,
                'total_doviz_toplam': total_doviz_toplam,
                'total_tutar_tl': total_tutar_tl,
                'avg_net_fiyat_tl': avg_net_fiyat_tl,
                'avg_net_fiyat_doviz': avg_net_fiyat_doviz
            },
            'filters': filters
        }

    except Exception as e:
        return {'error': str(e)}


def get_yagcilar_report3_data_for_mail(filters):
    """Mail için Rapor 3 verilerini getirir"""
    try:
        # Ay formatını kontrol et
        month_str = filters.get('month', '')
        if month_str:
            try:
                # Ay formatı: YYYY-MM
                year, month = map(int, month_str.split('-'))
                first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
                # Ayın son gününü bul
                _, last_day_of_month = calendar.monthrange(year, month)
                last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')
            except (ValueError, IndexError):
                now = datetime.now()
                year, month = now.year, now.month
                first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
                _, last_day_of_month = calendar.monthrange(year, month)
                last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')
        else:
            now = datetime.now()
            year, month = now.year, now.month
            first_day = datetime(year, month, 1).strftime('%Y-%m-%d')
            _, last_day_of_month = calendar.monthrange(year, month)
            last_day = datetime(year, month, last_day_of_month).strftime('%Y-%m-%d')

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                CONVERT(VARCHAR(10), [TARIH], 103) AS Tarih,
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE CONVERT(DATE, [TARIH]) BETWEEN ? AND ?
        """

        params = [first_day, last_day]

        # Filtre koşulları ekle
        cari_list = filters.get('cari', [])
        malzeme_grup_list = filters.get('malzeme_grup', [])
        satis_elemani_list = filters.get('satis_elemani', [])

        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [TARIH] ORDER BY [TARIH]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        result = []
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            tarih = row[0] or ""
            net_kg = float(row[1]) if row[1] else 0
            tutar_tl = float(row[2]) if row[2] else 0

            # Toplam değerler
            total_net_kg += net_kg
            total_tutar += tutar_tl

            # Birim fiyatları hesapla
            net_ort_fiyat_tl = tutar_tl / net_kg if net_kg > 0 else 0

            result.append({
                'tarih': tarih,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl,
                'net_ort_fiyat_tl': net_ort_fiyat_tl
            })

        cursor.close()
        conn.close()

        # Günlük ortalamalar hesapla
        day_count = len(result) if result else 1
        avg_daily_net_kg = total_net_kg / day_count
        avg_daily_net_price_tl = total_tutar / total_net_kg if total_net_kg > 0 else 0
        avg_daily_amount_tl = total_tutar / day_count

        return {
            'data': result,
            'summary': {
                'avg_daily_net_kg': avg_daily_net_kg,
                'avg_daily_net_price_tl': avg_daily_net_price_tl,
                'avg_daily_amount_tl': avg_daily_amount_tl,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar
            },
            'filters': {
                'month': month_str,
                'first_day': first_day,
                'last_day': last_day
            }
        }

    except Exception as e:
        return {'error': str(e)}


def get_yagcilar_report4_data_for_mail(filters):
    """Mail için Rapor 4 verilerini getirir"""
    try:
        # Yıl formatını kontrol et
        year_str = filters.get('year', '')
        if year_str:
            try:
                year = int(year_str)
            except ValueError:
                year = datetime.now().year
        else:
            year = datetime.now().year

        # SQL sorgusu oluştur
        sql_query = """
            SELECT 
                [AY],
                SUM([NET_KG]) AS NetKg,
                SUM([TUTAR]) AS TutarTL
            FROM BYT_SATIS_RAPORU_YAGCILAR
            WHERE [YIL] = ?
        """

        params = [year]

        # Filtre koşulları ekle
        cari_list = filters.get('cari', [])
        malzeme_grup_list = filters.get('malzeme_grup', [])
        satis_elemani_list = filters.get('satis_elemani', [])

        if cari_list:
            placeholders = ', '.join(['?' for _ in cari_list])
            sql_query += f" AND [CARI] IN ({placeholders})"
            params.extend(cari_list)

        if malzeme_grup_list:
            placeholders = ', '.join(['?' for _ in malzeme_grup_list])
            sql_query += f" AND [Malzeme Grup Kodu] IN ({placeholders})"
            params.extend(malzeme_grup_list)

        if satis_elemani_list:
            placeholders = ', '.join(['?' for _ in satis_elemani_list])
            sql_query += f" AND [SATIŞ ELEMANI] IN ({placeholders})"
            params.extend(satis_elemani_list)

        sql_query += " GROUP BY [AY] ORDER BY [AY]"

        # Veritabanına bağlan ve sorguyu çalıştır
        conn = get_db_connection2()
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        # Ay isimlerini hazırla
        ay_isimleri = [
            "OCAK", "ŞUBAT", "MART", "NİSAN", "MAYIS", "HAZİRAN",
            "TEMMUZ", "AĞUSTOS", "EYLÜL", "EKİM", "KASIM", "ARALIK"
        ]

        result = []
        total_net_kg = 0
        total_tutar = 0

        for row in cursor.fetchall():
            ay_no = int(row[0]) if row[0] else 0
            ay_name = ay_isimleri[ay_no - 1] if 1 <= ay_no <= 12 else f"Ay {ay_no}"
            net_kg = float(row[1]) if row[1] else 0
            tutar_tl = float(row[2]) if row[2] else 0

            # Toplam değerler
            total_net_kg += net_kg
            total_tutar += tutar_tl

            # Birim fiyatları hesapla
            net_ort_fiyat_tl = tutar_tl / net_kg if net_kg > 0 else 0

            result.append({
                'ay': str(ay_no),
                'sira_no': ay_no,
                'ay_name': ay_name,
                'net_kg': net_kg,
                'tutar_tl': tutar_tl,
                'net_ort_fiyat_tl': net_ort_fiyat_tl
            })

        cursor.close()
        conn.close()

        # Aylık ortalamalar hesapla
        month_count = len(result) if result else 1
        avg_monthly_net_kg = total_net_kg / month_count
        avg_monthly_net_price_tl = total_tutar / total_net_kg if total_net_kg > 0 else 0
        avg_monthly_amount_tl = total_tutar / month_count

        return {
            'data': result,
            'summary': {
                'avg_monthly_net_kg': avg_monthly_net_kg,
                'avg_monthly_net_price_tl': avg_monthly_net_price_tl,
                'avg_monthly_amount_tl': avg_monthly_amount_tl,
                'total_net_kg': total_net_kg,
                'total_tutar': total_tutar
            },
            'filters': {
                'year': year
            }
        }

    except Exception as e:
        return {'error': str(e)}


def get_yagcilar_report5_data_for_mail(filters):
    """Mail için Rapor 5 (Genel Analiz Raporu) verilerini getirir"""
    try:
        # Yıl ve ay bilgisini al
        year_str = filters.get('year', '')
        month_str = filters.get('month', '0')
        top_count = int(filters.get('top_count', '20'))

        if not year_str:
            year = datetime.now().year
        else:
            year = int(year_str)

        # Müşteri verilerini al (TL)
        customers_tl_data = []
        try:
            conn = get_db_connection2()
            cursor = conn.cursor()

            # Top customers by TL query
            sql_query = """
                SELECT 
                    [CARI],
                    SUM([NET_KG]) AS NetKg,
                    SUM([TUTAR]) AS TutarTL
                FROM BYT_SATIS_RAPORU_YAGCILAR
                WHERE [YIL] = ?
            """
            params = [year]

            if month_str != '0':
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)

            sql_query += """
                GROUP BY [CARI]
                ORDER BY SUM([TUTAR]) DESC
            """

            cursor.execute(sql_query, params)

            all_tl_data = []
            total_tl_kg = 0
            total_tl_amount = 0

            for row in cursor.fetchall():
                cari = row[0] or "Belirtilmemiş"
                net_kg = float(row[1]) if row[1] else 0
                tutar_tl = float(row[2]) if row[2] else 0

                all_tl_data.append({
                    'cari': cari,
                    'net_kg': net_kg,
                    'tutar_tl': tutar_tl
                })

                total_tl_kg += net_kg
                total_tl_amount += tutar_tl

            # İlk top_count kadar veriyi al
            for i, item in enumerate(all_tl_data[:top_count]):
                pay = (item['tutar_tl'] / total_tl_amount * 100) if total_tl_amount > 0 else 0
                customers_tl_data.append({
                    'sira': i + 1,
                    'cari': item['cari'],
                    'net_kg': item['net_kg'],
                    'tutar_tl': item['tutar_tl'],
                    'pay': pay
                })

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error getting top customers TL data: {str(e)}")

        # Müşteri verilerini al (KG)
        customers_kg_data = []
        try:
            conn = get_db_connection2()
            cursor = conn.cursor()

            # Top customers by KG query
            sql_query = """
                SELECT 
                    [CARI],
                    SUM([NET_KG]) AS NetKg,
                    SUM([TUTAR]) AS TutarTL
                FROM BYT_SATIS_RAPORU_YAGCILAR
                WHERE [YIL] = ?
            """
            params = [year]

            if month_str != '0':
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)

            sql_query += """
                GROUP BY [CARI]
                ORDER BY SUM([NET_KG]) DESC
            """

            cursor.execute(sql_query, params)

            all_kg_data = []
            total_kg = 0
            total_kg_amount = 0

            for row in cursor.fetchall():
                cari = row[0] or "Belirtilmemiş"
                net_kg = float(row[1]) if row[1] else 0
                tutar_tl = float(row[2]) if row[2] else 0

                all_kg_data.append({
                    'cari': cari,
                    'net_kg': net_kg,
                    'tutar_tl': tutar_tl
                })

                total_kg += net_kg
                total_kg_amount += tutar_tl

            # İlk top_count kadar veriyi al
            for i, item in enumerate(all_kg_data[:top_count]):
                pay = (item['net_kg'] / total_kg * 100) if total_kg > 0 else 0
                customers_kg_data.append({
                    'sira': i + 1,
                    'cari': item['cari'],
                    'net_kg': item['net_kg'],
                    'tutar_tl': item['tutar_tl'],
                    'pay': pay
                })

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error getting top customers KG data: {str(e)}")

        # Malzeme Grup verilerini al (TL)
        material_groups_tl_data = []
        try:
            conn = get_db_connection2()
            cursor = conn.cursor()

            sql_query = """
                SELECT 
                    [Malzeme Grup Kodu],
                    SUM([TUTAR]) AS TutarTL
                FROM BYT_SATIS_RAPORU_YAGCILAR
                WHERE [YIL] = ?
            """
            params = [year]

            if month_str != '0':
                month = int(month_str)
                if 1 <= month <= 12:
                    sql_query += " AND [AY] = ?"
                    params.append(month)

            sql_query += """
                GROUP BY [Malzeme Grup Kodu]
                ORDER BY SUM([TUTAR]) DESC
            """

            cursor.execute(sql_query, params)

            all_material_tl_data = []
            total_material_tl = 0

            for row in cursor.fetchall():
                malzeme_grup = row[0] or "Belirtilmemiş"
                tutar_tl = float(row[1]) if row[1] else 0

                all_material_tl_data.append({
                    'malzeme_grup': malzeme_grup,
                    'tutar_tl': tutar_tl
                })

                total_material_tl += tutar_tl

            # İlk top_count kadar veriyi al
            for i, item in enumerate(all_material_tl_data[:top_count]):
                pay = (item['tutar_tl'] / total_material_tl * 100) if total_material_tl > 0 else 0
                material_groups_tl_data.append({
                    'sira': i + 1,
                    'malzeme_grup': item['malzeme_grup'],
                    'tutar_tl': item['tutar_tl'],
                    'pay': pay
                })

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error getting top material groups TL data: {str(e)}")

        # Aylık satış trendleri
        monthly_trend_data = []
        try:
            conn = get_db_connection2()
            cursor = conn.cursor()

            sql_query = """
                SELECT 
                    [AY],
                    SUM([NET_KG]) AS NetKg,
                    SUM([TUTAR]) AS TutarTL
                FROM BYT_SATIS_RAPORU_YAGCILAR
                WHERE [YIL] = ?
                GROUP BY [AY]
                ORDER BY [AY]
            """
            params = [year]

            cursor.execute(sql_query, params)

            # Ay isimlerini hazırla
            ay_isimleri = [
                "OCAK", "ŞUBAT", "MART", "NİSAN", "MAYIS", "HAZİRAN",
                "TEMMUZ", "AĞUSTOS", "EYLÜL", "EKİM", "KASIM", "ARALIK"
            ]

            for row in cursor.fetchall():
                ay_no = int(row[0]) if row[0] else 0
                ay_name = ay_isimleri[ay_no - 1] if 1 <= ay_no <= 12 else f"Ay {ay_no}"
                net_kg = float(row[1]) if row[1] else 0
                tutar_tl = float(row[2]) if row[2] else 0

                monthly_trend_data.append({
                    'ay': str(ay_no),
                    'ay_name': ay_name,
                    'net_kg': net_kg,
                    'tutar_tl': tutar_tl
                })

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Error getting monthly sales trend data: {str(e)}")

        return {
            'customers_tl': {
                'data': customers_tl_data,
                'summary': {
                    'total_kg': total_tl_kg,
                    'total_amount': total_tl_amount
                }
            },
            'customers_kg': {
                'data': customers_kg_data,
                'summary': {
                    'total_kg': total_kg,
                    'total_amount': total_kg_amount
                }
            },
            'material_groups_tl': {
                'data': material_groups_tl_data
            },
            'monthly_trend': {
                'data': monthly_trend_data
            },
            'filters': {
                'year': year,
                'month': month_str
            }
        }

    except Exception as e:
        return {'error': str(e)}


def format_number(number, decimals=2):
    """Sayıları Türkçe formatta formatlar"""
    if number is None:
        return "0,00"
    return f"{number:,.{decimals}f}".replace(',', 'X').replace('.', ',').replace('X', '.')


def generate_yagcilar_mail_html(report_data, note, include_reports):
    """Mail için HTML içeriğini oluşturur"""
    # Güncel tarihi al
    current_date = datetime.now().strftime('%d.%m.%Y %H:%M')

    html_content = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>YAĞCILAR Genel Satış Raporu</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f8f9fa;
                color: #333;
                line-height: 1.6;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #282965 0%, #1e1a4f 100%);
                color: white;
                text-align: center;
                padding: 30px 20px;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .header p {{
                margin: 10px 0 0 0;
                font-size: 16px;
                opacity: 0.9;
            }}
            .content {{
                padding: 30px;
            }}
            .note {{
                background-color: #e3f2fd;
                border-left: 4px solid #2196f3;
                padding: 15px;
                margin: 20px 0;
                border-radius: 0 5px 5px 0;
            }}
            .note h3 {{
                margin: 0 0 10px 0;
                color: #1976d2;
                font-size: 18px;
            }}
            .report-section {{
                margin: 40px 0;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                overflow: hidden;
            }}
            .report-header {{
                background-color: #282965;
                color: white;
                padding: 15px 20px;
                font-size: 20px;
                font-weight: 600;
            }}
            .report-info {{
                background-color: #f5f5f5;
                padding: 15px 20px;
                border-bottom: 1px solid #e0e0e0;
                font-size: 14px;
                color: #666;
            }}
            .summary-cards {{
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                padding: 20px;
                background-color: #fafafa;
            }}
            .summary-card {{
                flex: 1;
                min-width: 180px;
                background-color: white;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }}
            .summary-label {{
                font-size: 12px;
                color: #666;
                text-transform: uppercase;
                margin-bottom: 5px;
            }}
            .summary-value {{
                font-size: 20px;
                font-weight: 600;
                color: #282965;
            }}
            .table-container {{
                padding: 20px;
                overflow-x: auto;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 14px;
                margin: 0;
            }}
            th {{
                background-color: #282965;
                color: white;
                padding: 12px 8px;
                text-align: center;
                font-weight: 600;
                border: 1px solid #fff;
            }}
            td {{
                padding: 10px 8px;
                text-align: center;
                border: 1px solid #e0e0e0;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            tr:hover {{
                background-color: #f0f8ff;
            }}
            .total-row {{
                background-color: #ffe0b2 !important;
                font-weight: bold;
                border-top: 2px solid #282965;
            }}
            .footer {{
                background-color: #f5f5f5;
                padding: 20px;
                text-align: center;
                color: #666;
                font-size: 12px;
            }}
            .highlight-blue {{
                background-color: rgba(227, 242, 253, 0.5);
                font-weight: 500;
            }}
            .highlight-green {{
                background-color: rgba(200, 230, 201, 0.5);
                font-weight: 500;
            }}
            .highlight-orange {{
                background-color: rgba(255, 224, 178, 0.5);
                font-weight: 500;
            }}
            @media (max-width: 768px) {{
                .summary-cards {{
                    flex-direction: column;
                }}
                .summary-card {{
                    min-width: 100%;
                }}
                table {{
                    font-size: 12px;
                }}
                th, td {{
                    padding: 8px 4px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏢 YAĞCILAR GENEL SATIŞ RAPORU</h1>
                <p>Tarih: {current_date}</p>
            </div>

            <div class="content">
    """

    # Not varsa ekle
    if note and note.strip():
        html_content += f"""
                <div class="note">
                    <h3>📋 Not</h3>
                    <p>{note}</p>
                </div>
        """

    # Rapor 1 - Malzeme Grup Raporu
    if include_reports.get('report1', True) and 'report1' in report_data:
        report1 = report_data['report1']
        if 'error' not in report1:
            data = report1.get('data', [])
            summary = report1.get('summary', {})
            filters = report1.get('filters', {})

            # Tarih veya ay bilgisini hazırla
            date_info = ""
            if 'date' in filters and filters['date']:
                try:
                    date_obj = datetime.strptime(filters['date'], '%Y-%m-%d')
                    date_info = f"Tarih: {date_obj.strftime('%d.%m.%Y')}"
                except ValueError:
                    pass
            elif 'month' in filters and filters['month']:
                try:
                    year, month = map(int, filters['month'].split('-'))
                    date_info = f"Ay: {month}.{year}"
                except (ValueError, IndexError):
                    pass

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📊 Malzeme Grubu Bazlı Özet Rapor
                    </div>
                    <div class="report-info">
                        {date_info}
                    </div>

                    <div class="summary-cards">
                        <div class="summary-card">
                            <div class="summary-label">Toplam Net KG</div>
                            <div class="summary-value">{format_number(summary.get('total_net_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Ortalama Net Fiyat (TL)</div>
                            <div class="summary-value">{format_number(summary.get('avg_net_price_tl', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Toplam Tutar (TL)</div>
                            <div class="summary-value">{format_number(summary.get('total_tutar', 0))} ₺</div>
                        </div>
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>MALZEME GRUP KODU</th>
                                    <th>NET KG</th>
                                    <th>NET ORT. FİYAT (TL)</th>
                                    <th>TUTAR (TL)</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            for item in data:
                html_content += f"""
                                <tr>
                                    <td style="text-align: left;">{item.get('malzeme_grup_kodu', '')}</td>
                                    <td class="highlight-blue">{format_number(item.get('net_kg', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('net_ort_fiyat_tl', 0))} ₺</td>
                                    <td class="highlight-orange">{format_number(item.get('tutar_tl', 0))} ₺</td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                            <tfoot>
                                <tr class="total-row">
                                    <td style="text-align: left;"><strong>TOPLAM</strong></td>
                                    <td><strong>{format_number(summary.get('total_net_kg', 0))}</strong></td>
                                    <td><strong>{format_number(summary.get('avg_net_price_tl', 0))} ₺</strong></td>
                                    <td><strong>{format_number(summary.get('total_tutar', 0))} ₺</strong></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            """

    # Rapor 2 - Detaylı Satış Raporu
    if include_reports.get('report2', True) and 'report2' in report_data:
        report2 = report_data['report2']
        if 'error' not in report2:
            data = report2.get('data', [])
            summary = report2.get('summary', {})
            filters = report2.get('filters', {})

            # Tarih veya ay bilgisini hazırla
            date_info = ""
            if 'date' in filters and filters['date']:
                try:
                    date_obj = datetime.strptime(filters['date'], '%Y-%m-%d')
                    date_info = f"Tarih: {date_obj.strftime('%d.%m.%Y')}"
                except ValueError:
                    pass
            elif 'month' in filters and filters['month']:
                try:
                    year, month = map(int, filters['month'].split('-'))
                    date_info = f"Ay: {month}.{year}"
                except (ValueError, IndexError):
                    pass

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📈 Detaylı Satış Raporu
                    </div>
                    <div class="report-info">
                        {date_info} | Toplam {len(data)} kayıt
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>CARİ</th>
                                    <th>SATIŞ ELEMANI</th>
                                    <th>MALZEME GRUP</th>
                                    <th>ÜRÜN ADI</th>
                                    <th>NET KG</th>
                                    <th>NET ORT. FİYAT (TL)</th>
                                    <th>DÖVİZ TÜRÜ</th>
                                    <th>DÖVİZLİ TUTAR</th>
                                    <th>TUTAR TL</th>
                                    <th>ÖDEME TİPİ</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            # E-posta boyutunu sınırlamak için ilk 50 kaydı ekle
            max_records = min(50, len(data))
            for i in range(max_records):
                item = data[i]
                html_content += f"""
                                <tr>
                                    <td style="text-align: left;">{item.get('cari', '')}</td>
                                    <td>{item.get('satis_elemani', '')}</td>
                                    <td>{item.get('malzeme_grup', '')}</td>
                                    <td style="text-align: left;">{item.get('urun_adi', '')}</td>
                                    <td class="highlight-blue">{format_number(item.get('net_kg', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('net_ort_fiyat_tl', 0))} ₺</td>
                                    <td>{item.get('doviz_turu', '')}</td>
                                    <td class="highlight-green">{format_number(item.get('doviz_toplam', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('tutar_tl', 0))} ₺</td>
                                    <td>{item.get('odeme_tipi', '')}</td>
                                </tr>
                """

            if len(data) > max_records:
                html_content += f"""
                                <tr>
                                    <td colspan="10" style="text-align: center; font-style: italic; color: #666;">
                                        ... ve {len(data) - max_records} kayıt daha (Detaylar için sisteme giriş yapın)
                                    </td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                            <tfoot>
                                <tr class="total-row">
                                    <td colspan="4" style="text-align: left;"><strong>TOPLAM</strong></td>
                                    <td><strong>{format_number(summary.get('total_net_kg', 0))}</strong></td>
                                    <td><strong>{format_number(summary.get('avg_net_fiyat_tl', 0))} ₺</strong></td>
                                    <td></td>
                                    <td><strong>{format_number(summary.get('total_doviz_toplam', 0))}</strong></td>
                                    <td><strong>{format_number(summary.get('total_tutar_tl', 0))} ₺</strong></td>
                                    <td></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            """

    # Rapor 3 - Günlük Hedef Raporu
    if include_reports.get('report3', True) and 'report3' in report_data:
        report3 = report_data['report3']
        if 'error' not in report3:
            data = report3.get('data', [])
            summary = report3.get('summary', {})
            filters = report3.get('filters', {})

            month_info = filters.get('month', 'Belirtilmemiş')

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📅 Günlük Hedef Tablo
                    </div>
                    <div class="report-info">
                        Ay: {month_info} | {filters.get('first_day', '')} - {filters.get('last_day', '')}
                    </div>

                    <div class="summary-cards">
                        <div class="summary-card">
                            <div class="summary-label">Günlük Ort. Net KG</div>
                            <div class="summary-value">{format_number(summary.get('avg_daily_net_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Günlük Net Ort. Fiyat (TL)</div>
                            <div class="summary-value">{format_number(summary.get('avg_daily_net_price_tl', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Günlük Ort. Tutar (TL)</div>
                            <div class="summary-value">{format_number(summary.get('avg_daily_amount_tl', 0))} ₺</div>
                        </div>
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>TARİH</th>
                                    <th>NET KG</th>
                                    <th>NET ORT. FİYAT (TL)</th>
                                    <th>TUTAR (TL)</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            for item in data:
                html_content += f"""
                                <tr>
                                    <td>{item.get('tarih', '')}</td>
                                    <td class="highlight-blue">{format_number(item.get('net_kg', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('net_ort_fiyat_tl', 0))} ₺</td>
                                    <td class="highlight-orange">{format_number(item.get('tutar_tl', 0))} ₺</td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                            <tfoot>
                                <tr class="total-row">
                                    <td><strong>TOPLAM</strong></td>
                                    <td><strong>{format_number(summary.get('total_net_kg', 0))}</strong></td>
                                    <td><strong>{format_number(summary.get('avg_daily_net_price_tl', 0))} ₺</strong></td>
                                    <td><strong>{format_number(summary.get('total_tutar', 0))} ₺</strong></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            """

    # Rapor 4 - Aylık Hedef Raporu
    if include_reports.get('report4', True) and 'report4' in report_data:
        report4 = report_data['report4']
        if 'error' not in report4:
            data = report4.get('data', [])
            summary = report4.get('summary', {})
            filters = report4.get('filters', {})

            year_info = filters.get('year', 'Belirtilmemiş')

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📆 Aylık Hedef Tablo
                    </div>
                    <div class="report-info">
                        Yıl: {year_info}
                    </div>

                    <div class="summary-cards">
                        <div class="summary-card">
                            <div class="summary-label">Aylık Ort. Net KG</div>
                            <div class="summary-value">{format_number(summary.get('avg_monthly_net_kg', 0))}</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Aylık Net Ort. Fiyat (TL)</div>
                            <div class="summary-value">{format_number(summary.get('avg_monthly_net_price_tl', 0))} ₺</div>
                        </div>
                        <div class="summary-card">
                            <div class="summary-label">Aylık Ort. Tutar (TL)</div>
                            <div class="summary-value">{format_number(summary.get('avg_monthly_amount_tl', 0))} ₺</div>
                        </div>
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>SIRA NO</th>
                                    <th>AY</th>
                                    <th>NET KG</th>
                                    <th>NET ORT. FİYAT (TL)</th>
                                    <th>TUTAR (TL)</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            # Ayları sıra numarasına göre sırala
            sorted_data = sorted(data, key=lambda x: int(x.get('ay', '0')))

            for item in sorted_data:
                html_content += f"""
                                <tr>
                                    <td>{item.get('sira_no', item.get('ay', ''))}</td>
                                    <td>{item.get('ay_name', '')}</td>
                                    <td class="highlight-blue">{format_number(item.get('net_kg', 0))}</td>
                                    <td class="highlight-green">{format_number(item.get('net_ort_fiyat_tl', 0))} ₺</td>
                                    <td class="highlight-orange">{format_number(item.get('tutar_tl', 0))} ₺</td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                            <tfoot>
                                <tr class="total-row">
                                    <td colspan="2"><strong>TOPLAM</strong></td>
                                    <td><strong>{format_number(summary.get('total_net_kg', 0))}</strong></td>
                                    <td><strong>{format_number(summary.get('avg_monthly_net_price_tl', 0))} ₺</strong></td>
                                    <td><strong>{format_number(summary.get('total_tutar', 0))} ₺</strong></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            """
    if include_reports.get('report5', False) and 'report5' in report_data:
        report5 = report_data['report5']
        if 'error' not in report5:
            filters = report5.get('filters', {})
            customers_tl = report5.get('customers_tl', {})
            customers_kg = report5.get('customers_kg', {})
            material_groups_tl = report5.get('material_groups_tl', {})
            monthly_trend = report5.get('monthly_trend', {})

            year_info = filters.get('year', 'Belirtilmemiş')
            month_info = "Tüm Aylar" if filters.get('month', '0') == '0' else filters.get('month', '')

            html_content += f"""
                <div class="report-section">
                    <div class="report-header">
                        📊 Genel Analiz Raporu
                    </div>
                    <div class="report-info">
                        Yıl: {year_info} | Ay: {month_info}
                    </div>

                    <!-- Top Customers by TL -->
                    <div style="margin: 20px 0;">
                        <h3 style="background-color: #f5f5f5; padding: 10px; margin: 0;">En Çok Satış Yapılan Müşteriler - Tutar (TL) Bazlı</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>SIRA</th>
                                        <th>CARİ</th>
                                        <th>NET KG</th>
                                        <th>TUTAR (TL)</th>
                                        <th>TOPLAM İÇİNDEKİ PAYI (%)</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            customers_tl_data = customers_tl.get('data', [])
            for item in customers_tl_data[:10]:  # Sadece ilk 10 müşteriyi göster
                html_content += f"""
                                    <tr>
                                        <td>{item.get('sira', '')}</td>
                                        <td style="text-align: left;">{item.get('cari', '')}</td>
                                        <td>{format_number(item.get('net_kg', 0))}</td>
                                        <td>{format_number(item.get('tutar_tl', 0))} ₺</td>
                                        <td>{format_number(item.get('pay', 0), 1)}%</td>
                                    </tr>
                """

            customers_tl_summary = customers_tl.get('summary', {})
            html_content += f"""
                                </tbody>
                                <tfoot>
                                    <tr class="total-row">
                                        <td colspan="2"><strong>TOPLAM</strong></td>
                                        <td><strong>{format_number(customers_tl_summary.get('total_kg', 0))}</strong></td>
                                        <td><strong>{format_number(customers_tl_summary.get('total_amount', 0))} ₺</strong></td>
                                        <td><strong>100%</strong></td>
                                    </tr>
                                </tfoot>
                            </table>
                        </div>
                    </div>

                    <!-- Top Customers by KG -->
                    <div style="margin: 20px 0;">
                        <h3 style="background-color: #f5f5f5; padding: 10px; margin: 0;">En Çok Satış Yapılan Müşteriler - Net KG Bazlı</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>SIRA</th>
                                        <th>CARİ</th>
                                        <th>NET KG</th>
                                        <th>TUTAR (TL)</th>
                                        <th>TOPLAM İÇİNDEKİ PAYI (%)</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            customers_kg_data = customers_kg.get('data', [])
            for item in customers_kg_data[:10]:  # Sadece ilk 10 müşteriyi göster
                html_content += f"""
                                    <tr>
                                        <td>{item.get('sira', '')}</td>
                                        <td style="text-align: left;">{item.get('cari', '')}</td>
                                        <td>{format_number(item.get('net_kg', 0))}</td>
                                        <td>{format_number(item.get('tutar_tl', 0))} ₺</td>
                                        <td>{format_number(item.get('pay', 0), 1)}%</td>
                                    </tr>
                """

            customers_kg_summary = customers_kg.get('summary', {})
            html_content += f"""
                                </tbody>
                                <tfoot>
                                    <tr class="total-row">
                                        <td colspan="2"><strong>TOPLAM</strong></td>
                                        <td><strong>{format_number(customers_kg_summary.get('total_kg', 0))}</strong></td>
                                        <td><strong>{format_number(customers_kg_summary.get('total_amount', 0))} ₺</strong></td>
                                        <td><strong>100%</strong></td>
                                    </tr>
                                </tfoot>
                            </table>
                        </div>
                    </div>

                    <!-- Top Material Groups by TL -->
                    <div style="margin: 20px 0;">
                        <h3 style="background-color: #f5f5f5; padding: 10px; margin: 0;">En Çok Satılan Malzeme Grupları - Tutar (TL)</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>SIRA</th>
                                        <th>MALZEME GRUP</th>
                                        <th>TUTAR (TL)</th>
                                        <th>PAY (%)</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            material_groups_tl_data = material_groups_tl.get('data', [])
            for item in material_groups_tl_data[:10]:  # Sadece ilk 10 malzeme grubunu göster
                html_content += f"""
                                    <tr>
                                        <td>{item.get('sira', '')}</td>
                                        <td style="text-align: left;">{item.get('malzeme_grup', '')}</td>
                                        <td>{format_number(item.get('tutar_tl', 0))} ₺</td>
                                        <td>{format_number(item.get('pay', 0), 1)}%</td>
                                    </tr>
                """

            html_content += f"""
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Monthly Sales Trend -->
                    <div style="margin: 20px 0;">
                        <h3 style="background-color: #f5f5f5; padding: 10px; margin: 0;">Aylık Satış Trendi</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>AY</th>
                                        <th>NET KG</th>
                                        <th>TUTAR (TL)</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            monthly_trend_data = monthly_trend.get('data', [])
            monthly_trend_data.sort(key=lambda x: int(x.get('ay', '0')))

            for item in monthly_trend_data:
                html_content += f"""
                                    <tr>
                                        <td>{item.get('ay_name', '')}</td>
                                        <td>{format_number(item.get('net_kg', 0))}</td>
                                        <td>{format_number(item.get('tutar_tl', 0))} ₺</td>
                                    </tr>
                """

            html_content += f"""
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            """
    # Sayfa sonunu kapat
    html_content += """
            </div>
            <div class="footer">
                <p>Bu rapor BYT Digital bilgi sistemi tarafından otomatik olarak oluşturulmuştur.</p>
                <p>© BYT DIGITAL</p>
            </div>
        </div>
    </body>
    </html>
    """

    return html_content


# Gmail SMTP Ayarları için Ortak Fonksiyon (İsteğe bağlı)
def send_gmail_email(sender_email, sender_password, recipients, subject, html_content):
    """Gmail SMTP ile e-posta gönderme için ortak fonksiyon"""
    try:
        # E-posta konteyneri oluştur
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = ', '.join(recipients) if isinstance(recipients, list) else recipients

        # HTML içeriği ekle
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(html_part)

        # Gmail SMTP ile mail gönder
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Gmail için TLS gerekli
        server.login(sender_email, sender_password)

        if isinstance(recipients, list):
            for recipient in recipients:
                server.sendmail(sender_email, recipient, msg.as_string())
        else:
            server.sendmail(sender_email, recipients, msg.as_string())

        server.quit()
        return True

    except Exception as e:
        print(f"E-posta gönderilirken hata oluştu: {e}")
        return False


import threading
import time
import sqlite3
import os
from datetime import datetime, timedelta
from functools import wraps

# *** ÇİFTE MAİL GÖNDERİMİNİ ÖNLEMEİÇİN GLOBAL DEĞİŞKENLER ***
mail_sending_lock = threading.Lock()
mail_sending_status = {
    'is_sending': False,
    'last_send_time': None,
    'send_count_today': 0,
    'last_send_date': None
}

# ============================================================================
# GLOBAL DEĞİŞKENLER - SINGLETON PATTERN
# ============================================================================

_scheduler_instance = None
_mail_lock = threading.RLock()  # Reentrant lock
_daily_mail_sent = {}  # Memory cache for daily mails
_process_id = str(uuid.uuid4())[:8]  # Unique process identifier


# ============================================================================
# ATOMIC DOSYA İŞLEMLERİ
# ============================================================================

def atomic_write_file(filepath, content):
    """Atomic file writing - race condition'ları önler"""
    temp_file = f"{filepath}.tmp.{_process_id}"
    try:
        with open(temp_file, 'w') as f:
            f.write(content)

        # Atomic move (POSIX systems)
        if os.name == 'posix':
            os.rename(temp_file, filepath)
        else:
            # Windows için
            if os.path.exists(filepath):
                os.remove(filepath)
            os.rename(temp_file, filepath)
        return True
    except Exception as e:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except:
            pass
        print(f"[ERROR] Atomic write failed: {e}")
        return False


def atomic_read_file(filepath):
    """Atomic file reading"""
    try:
        with open(filepath, 'r') as f:
            return f.read().strip()
    except:
        return None


# ============================================================================
# GÜNLÜK MAİL KONTROL SİSTEMİ
# ============================================================================

def get_daily_mail_status_file():
    """Günlük mail durum dosyası"""
    today = datetime.now().strftime('%Y-%m-%d')
    return f"daily_mail_status_{today}.json"


def is_daily_mail_sent():
    """Bugün mail gönderildi mi? - ULTRA SAFE"""
    today = datetime.now().strftime('%Y-%m-%d')

    # 1. Memory cache kontrolü
    if today in _daily_mail_sent and _daily_mail_sent[today]:
        print(f"[INFO] Daily mail sent (memory cache): {today}")
        return True

    # 2. Dosya kontrolü
    status_file = get_daily_mail_status_file()
    if os.path.exists(status_file):
        content = atomic_read_file(status_file)
        if content:
            try:
                data = json.loads(content)
                if data.get('sent') and data.get('date') == today:
                    # Memory cache'i güncelle
                    _daily_mail_sent[today] = True
                    print(f"[INFO] Daily mail sent (file cache): {today}")
                    return True
            except:
                pass

    # 3. Legacy flag dosyası kontrolü
    flag_file = f"mail_sent_{today}.flag"
    if os.path.exists(flag_file):
        _daily_mail_sent[today] = True
        print(f"[INFO] Daily mail sent (legacy flag): {today}")
        return True

    return False


def mark_daily_mail_sent():
    """Günlük mail gönderildi olarak işaretle - ULTRA SAFE"""
    today = datetime.now().strftime('%Y-%m-%d')

    # 1. Memory cache
    _daily_mail_sent[today] = True

    # 2. Status dosyası
    status_file = get_daily_mail_status_file()
    data = {
        'sent': True,
        'date': today,
        'timestamp': datetime.now().isoformat(),
        'process_id': _process_id
    }

    success = atomic_write_file(status_file, json.dumps(data, indent=2))
    if success:
        print(f"[SUCCESS] Daily mail marked as sent: {today}")
    else:
        print(f"[ERROR] Failed to mark daily mail as sent: {today}")

    # 3. Legacy flag dosyası (backward compatibility)
    flag_file = f"mail_sent_{today}.flag"
    try:
        with open(flag_file, 'w') as f:
            f.write(f"{datetime.now().isoformat()}\n{_process_id}")
    except:
        pass

    # 4. Eski dosyaları temizle
    cleanup_old_files()


def cleanup_old_files():
    """7 günden eski dosyaları temizle"""
    try:
        cutoff_date = datetime.now() - timedelta(days=7)
        cutoff_str = cutoff_date.strftime('%Y-%m-%d')

        for filename in os.listdir('.'):
            if filename.startswith('daily_mail_status_') and filename.endswith('.json'):
                try:
                    date_part = filename.replace('daily_mail_status_', '').replace('.json', '')
                    if date_part < cutoff_str:
                        os.remove(filename)
                except:
                    pass
            elif filename.startswith('mail_sent_') and filename.endswith('.flag'):
                try:
                    date_part = filename.replace('mail_sent_', '').replace('.flag', '')
                    if date_part < cutoff_str:
                        os.remove(filename)
                except:
                    pass
    except Exception as e:
        print(f"[WARNING] Cleanup error: {e}")


# ============================================================================
# ULTRA-SAFE MAIL GÖNDERİM GUARD
# ============================================================================

def ultra_safe_mail_guard(func):
    """Ultra güvenli mail gönderim guard - çifte gönderim kesinlikle engellenecek"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        with _mail_lock:
            # 1. Günlük mail kontrolü
            if is_daily_mail_sent():
                print("[BLOCKED] Daily mail already sent - operation blocked")
                return {'success': False, 'error': 'Daily mail already sent'}

            # 2. Process-level lock
            lock_file = f"mail_sending_lock_{_process_id}"
            if os.path.exists(lock_file):
                print("[BLOCKED] Process-level lock exists - operation blocked")
                return {'success': False, 'error': 'Mail sending already in progress'}

            # 3. Global lock
            global_lock_file = "global_mail_sending.lock"
            if os.path.exists(global_lock_file):
                # Lock dosyasının yaşını kontrol et (5 dakikadan eski ise sil)
                try:
                    lock_age = time.time() - os.path.getmtime(global_lock_file)
                    if lock_age > 300:  # 5 dakika
                        os.remove(global_lock_file)
                        print("[INFO] Stale global lock removed")
                    else:
                        print("[BLOCKED] Global lock exists - operation blocked")
                        return {'success': False, 'error': 'Another process is sending mail'}
                except:
                    pass

            # 4. Lock dosyalarını oluştur
            try:
                atomic_write_file(lock_file, f"{datetime.now().isoformat()}\n{_process_id}")
                atomic_write_file(global_lock_file, f"{datetime.now().isoformat()}\n{_process_id}")
            except Exception as e:
                print(f"[ERROR] Failed to create locks: {e}")
                return {'success': False, 'error': 'Failed to create locks'}

            print(f"[INFO] Mail sending started (Process: {_process_id})")

            try:
                # Fonksiyonu çalıştır
                result = func(*args, **kwargs)

                # Başarılı ise işaretle
                if result.get('success', False):
                    mark_daily_mail_sent()
                    print("[SUCCESS] Mail sent successfully")
                else:
                    print(f"[ERROR] Mail sending failed: {result.get('error', 'Unknown error')}")

                return result

            except Exception as e:
                error_msg = f"Mail sending exception: {str(e)}"
                print(f"[ERROR] {error_msg}")
                return {'success': False, 'error': error_msg}

            finally:
                # Lock dosyalarını temizle
                try:
                    if os.path.exists(lock_file):
                        os.remove(lock_file)
                    if os.path.exists(global_lock_file):
                        os.remove(global_lock_file)
                    print("[INFO] Locks removed")
                except Exception as e:
                    print(f"[WARNING] Lock cleanup error: {e}")

    return wrapper


# ============================================================================
# SCHEDULER SİSTEMİ - SINGLETON PATTERN
# ============================================================================

def get_scheduler():
    """Singleton scheduler instance"""
    global _scheduler_instance
    return _scheduler_instance


def create_scheduler():
    """Yeni scheduler oluştur - sadece bir kez"""
    global _scheduler_instance

    with _mail_lock:
        if _scheduler_instance is not None:
            print("[WARNING] Scheduler already exists, stopping old one")
            try:
                if _scheduler_instance.running:
                    _scheduler_instance.shutdown(wait=False)
            except:
                pass
            _scheduler_instance = None

        try:
            _scheduler_instance = BackgroundScheduler()
            print(f"[INFO] New scheduler created (Process: {_process_id})")
            return _scheduler_instance
        except Exception as e:
            print(f"[ERROR] Scheduler creation failed: {e}")
            return None


def add_daily_mail_job():
    """Günlük mail job'ını ekle - KESIN TEK JOB"""
    scheduler = get_scheduler()
    if not scheduler:
        print("[ERROR] No scheduler available")
        return False

    # Mevcut tüm jobları sil
    try:
        all_jobs = scheduler.get_jobs()
        for job in all_jobs:
            scheduler.remove_job(job.id)
            print(f"[INFO] Removed existing job: {job.id}")
    except Exception as e:
        print(f"[WARNING] Job cleanup error: {e}")

    # Tek job ekle
    job_id = f"daily_mail_{_process_id}"
    try:
        scheduler.add_job(
            func=send_daily_mail_internal,
            trigger="cron",
            hour=19,
            minute=15,
            second=0,
            id=job_id,
            max_instances=1,
            coalesce=True,
            replace_existing=True,
            misfire_grace_time=60
        )
        print(f"[SUCCESS] Daily mail job added: {job_id}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to add daily mail job: {e}")
        return False


def start_scheduler():
    """Scheduler'ı başlat"""
    scheduler = get_scheduler()
    if not scheduler:
        return False

    try:
        if not scheduler.running:
            scheduler.start()
            print("[SUCCESS] Scheduler started")

        # Job sayısını kontrol et
        jobs = scheduler.get_jobs()
        print(f"[INFO] Active jobs: {len(jobs)}")
        for job in jobs:
            print(f"[INFO] Job: {job.id} - Next run: {job.next_run_time}")

        return True
    except Exception as e:
        print(f"[ERROR] Scheduler start failed: {e}")
        return False


def stop_scheduler():
    """Scheduler'ı durdur"""
    global _scheduler_instance

    if _scheduler_instance:
        try:
            if _scheduler_instance.running:
                _scheduler_instance.shutdown(wait=False)
                print("[INFO] Scheduler stopped")
        except Exception as e:
            print(f"[WARNING] Scheduler stop error: {e}")
        finally:
            _scheduler_instance = None


# ============================================================================
# MAİL GÖNDERİM FONKSİYONLARI
# ============================================================================

@ultra_safe_mail_guard
def send_daily_mail_internal():
    """Günlük mail gönderen ana fonksiyon - ULTRA SAFE"""
    try:
        print("[INFO] Starting daily mail generation...")

        today = datetime.now().strftime('%Y-%m-%d')
        current_month = datetime.now().strftime('%Y-%m')
        current_year = datetime.now().year

        # Mail verileri
        mail_data = {
            'subject': f'{datetime.now().strftime("%d.%m.%Y")} - YDÇ Metal Günlük Satış Raporu',
            'recipients': ['huseyinyagci@ydcmetal.com.tr', 'yunus@beymasmetal.com.tr'],
            'cc_recipients': ['hasan@staryagcilar.com.tr', 'kadiryagci@staryagcilar.com.tr',
                              'veli@staryagcilar.com.tr', 'turancam@ydcmetal.com.tr',
                              'bayramyagci@ydcmetal.com.tr', 'bayramyagci@yagcilar.com.tr'],
            'note': 'Bu mail otomatik olarak sistem tarafından gönderilmiştir.',
            'include_reports': {
                'report1': True,
                'report2': True,
                'report3': True,
                'report4': True,
                'report5': False
            },
            'filters': {
                'report1': {'date': today, 'cari': [], 'muhasebe_grup': [], 'satis_elemani': []},
                'report2': {'date': today, 'cari': [], 'malzeme_grup': [], 'satis_elemani': []},
                'report3': {'month': current_month, 'cari': [], 'muhasebe_grup': [], 'satis_elemani': []},
                'report4': {'year': str(current_year), 'cari': [], 'muhasebe_grup': [], 'satis_elemani': []}
            }
        }

        # Mail gönder
        return send_mail_via_smtp(mail_data)

    except Exception as e:
        print(f"[ERROR] Daily mail internal error: {e}")
        return {'success': False, 'error': str(e)}


def send_mail_via_smtp(mail_data):
    """SMTP ile mail gönder"""
    try:
        # Gmail ayarları
        sender_email = "yagcilarholding1@gmail.com"
        sender_password = "bqnp sius nztz padc"
        sender_name = "Yağcılar Holding"

        recipients = mail_data.get('recipients', [])
        cc_recipients = mail_data.get('cc_recipients', [])

        if not recipients:
            return {'success': False, 'error': 'No recipients'}

        print(f"[INFO] Preparing mail - Recipients: {len(recipients)}, CC: {len(cc_recipients)}")

        # E-posta oluştur
        msg = MIMEMultipart('alternative')
        msg['Subject'] = mail_data.get('subject', 'YDC Günlük Rapor')
        msg['From'] = f"{sender_name} <{sender_email}>"
        msg['To'] = ', '.join(recipients)

        if cc_recipients:
            msg['Cc'] = ', '.join(cc_recipients)

        # HTML içerik oluştur (bu fonksiyonları mevcut kodunuzdan kullanın)
        print("[INFO] Generating report data...")
        report_data = {}
        include_reports = mail_data.get('include_reports', {})
        filters = mail_data.get('filters', {})

        # Raporları topla (mevcut fonksiyonlarınızı kullanın)
        if include_reports.get('report1', True):
            report_data['report1'] = get_report1_data_for_mail(filters.get('report1', {}))
        if include_reports.get('report2', True):
            report_data['report2'] = get_report2_data_for_mail(filters.get('report2', {}))
        if include_reports.get('report3', True):
            report_data['report3'] = get_report3_data_for_mail(filters.get('report3', {}))
        if include_reports.get('report4', True):
            report_data['report4'] = get_report4_data_for_mail(filters.get('report4', {}))

        print("[INFO] Generating HTML content...")
        html_content = generate_mail_html(report_data, mail_data.get('note', ''), include_reports)
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(html_part)

        # SMTP gönder
        print("[INFO] Connecting to SMTP...")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)

        print("[INFO] Sending mail...")
        all_recipients = recipients + cc_recipients
        server.sendmail(sender_email, all_recipients, msg.as_string())
        server.quit()

        print(f"[SUCCESS] Mail sent to {len(recipients)} recipients and {len(cc_recipients)} CC")
        return {
            'success': True,
            'message': f'Mail sent successfully to {len(recipients)} recipients and {len(cc_recipients)} CC'
        }

    except Exception as e:
        print(f"[ERROR] SMTP error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# MANUEL MAİL GÖNDERİM
# ============================================================================

def send_manual_mail(mail_data):
    """Manuel mail gönderimi - günlük limit kontrolü ile"""
    # Basit rate limiting - günde max 5 manuel mail
    today = datetime.now().strftime('%Y-%m-%d')
    manual_count_file = f"manual_mail_count_{today}.txt"

    try:
        count = 0
        if os.path.exists(manual_count_file):
            content = atomic_read_file(manual_count_file)
            if content and content.isdigit():
                count = int(content)

        if count >= 5:
            return {'success': False, 'error': 'Daily manual mail limit exceeded (5/day)'}

        # Mail gönder
        result = send_mail_via_smtp(mail_data)

        # Başarılı ise sayacı artır
        if result.get('success', False):
            atomic_write_file(manual_count_file, str(count + 1))

        return result

    except Exception as e:
        print(f"[ERROR] Manual mail error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# SETUP VE KONTROL FONKSİYONLARI
# ============================================================================

def setup_auto_mail_system():
    """Otomatik mail sistemini kur - MAIN ENTRY POINT"""
    print(f"[INFO] Setting up auto mail system (Process: {_process_id})")

    try:
        # Eski dosyaları temizle
        cleanup_old_files()

        # Scheduler oluştur
        scheduler = create_scheduler()
        if not scheduler:
            return False

        # Job ekle
        if not add_daily_mail_job():
            return False

        # Başlat
        if not start_scheduler():
            return False

        # Kapanış fonksiyonunu kaydet
        atexit.register(stop_scheduler)

        print("[SUCCESS] Auto mail system setup completed")
        return True

    except Exception as e:
        print(f"[ERROR] Setup failed: {e}")
        return False


def get_system_status():
    """Sistem durumunu getir"""
    scheduler = get_scheduler()
    today = datetime.now().strftime('%Y-%m-%d')

    return {
        'process_id': _process_id,
        'scheduler_running': scheduler is not None and scheduler.running if scheduler else False,
        'active_jobs': len(scheduler.get_jobs()) if scheduler and scheduler.running else 0,
        'daily_mail_sent': is_daily_mail_sent(),
        'daily_mail_status_file_exists': os.path.exists(get_daily_mail_status_file()),
        'global_lock_exists': os.path.exists("global_mail_sending.lock"),
        'process_lock_exists': os.path.exists(f"mail_sending_lock_{_process_id}"),
        'manual_mail_count': get_manual_mail_count(),
        'next_scheduled_run': get_next_run_time()
    }


def get_manual_mail_count():
    """Bugünkü manuel mail sayısı"""
    today = datetime.now().strftime('%Y-%m-%d')
    count_file = f"manual_mail_count_{today}.txt"

    if os.path.exists(count_file):
        content = atomic_read_file(count_file)
        if content and content.isdigit():
            return int(content)
    return 0


def get_next_run_time():
    """Sonraki mail zamanı"""
    scheduler = get_scheduler()
    if scheduler and scheduler.running:
        jobs = scheduler.get_jobs()
        if jobs:
            return jobs[0].next_run_time.isoformat() if jobs[0].next_run_time else None
    return None


def force_reset_daily_mail():
    """Günlük mail durumunu sıfırla - SADECE TEST İÇİN"""
    today = datetime.now().strftime('%Y-%m-%d')

    # Memory cache'i temizle
    if today in _daily_mail_sent:
        del _daily_mail_sent[today]

    # Dosyaları sil
    status_file = get_daily_mail_status_file()
    flag_file = f"mail_sent_{today}.flag"

    for file in [status_file, flag_file]:
        try:
            if os.path.exists(file):
                os.remove(file)
                print(f"[INFO] Removed: {file}")
        except Exception as e:
            print(f"[WARNING] Failed to remove {file}: {e}")

    print("[WARNING] Daily mail status reset - USE ONLY FOR TESTING!")


def emergency_cleanup():
    """Acil durum temizliği - her şeyi sıfırla"""
    print("[WARNING] Emergency cleanup initiated...")

    # Scheduler'ı durdur
    stop_scheduler()

    # Tüm lock dosyalarını sil
    for filename in os.listdir('.'):
        if any(pattern in filename for pattern in ['mail_sending_', 'global_mail_', 'manual_mail_count_']):
            try:
                os.remove(filename)
                print(f"[INFO] Removed: {filename}")
            except:
                pass

    # Memory cache'i temizle
    _daily_mail_sent.clear()

    print("[SUCCESS] Emergency cleanup completed")

@app.route('/cari_bakiye')
@permission_required(menu_id=1026, permission_type='view')
def cari_bakiye():
    from datetime import datetime  # Import ekle
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection2()
        cursor = conn.cursor()

        # Varsayılan olarak bugünün tarihini al
        selected_date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))

        # Tarih formatını kontrol et (güvenlik)
        try:
            datetime.strptime(selected_date, '%Y-%m-%d')
        except ValueError:
            selected_date = datetime.now().strftime('%Y-%m-%d')
        selected_cari = request.args.get('cari', '')

        # Tarih formatını kontrol et (güvenlik)
        try:
            datetime.strptime(selected_date, '%Y-%m-%d')
        except ValueError:
            selected_date = datetime.now().strftime('%Y-%m-%d')

        # Multi-select değerleri al
        selected_firmas = request.args.get('firmas', '')
        selected_cari_grups = request.args.get('cari_grups', '')
        selected_cari_turs = request.args.get('cari_turs', '')
        selected_durums = request.args.get('durums', '')

        # Eğer hiç değer yoksa (ilk yükleme), default değerleri ayarla
        if not any([selected_firmas, selected_cari_grups, selected_cari_turs, selected_durums]):
            selected_firmas = ''
            # Cari grup için tüm değerleri seç (boş dahil)
            try:
                cari_grup_query = """
                SELECT DISTINCT CL.SPECODE5 AS [CARİ GRUP]
                FROM (
                    SELECT SPECODE5 FROM LG_225_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%')
                    UNION
                    SELECT SPECODE5 FROM LG_325_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%')
                    UNION
                    SELECT SPECODE5 FROM LG_425_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%')
                ) CL
                ORDER BY [CARİ GRUP]
                """
                cursor.execute(cari_grup_query)
                all_cari_grups = [row[0] if row[0] is not None else '' for row in cursor.fetchall()]
                selected_cari_grups = ','.join(all_cari_grups)
            except:
                selected_cari_grups = ''

            selected_cari_turs = ''
            selected_durums = ''

        # Liste haline getir ve temizle
        firma_filter = [f.strip() for f in selected_firmas.split(',') if f.strip()] if selected_firmas else []
        cari_grup_filter = [g.strip() if g.strip() else '' for g in selected_cari_grups.split(',') if
                            g or g == ''] if selected_cari_grups else []
        cari_tur_filter = [t.strip() if t.strip() else '' for t in selected_cari_turs.split(',') if
                           t or t == ''] if selected_cari_turs else []
        durum_filter = [d.strip() for d in selected_durums.split(',') if d.strip()] if selected_durums else []

        # Firma listesi
        firma_list = ['225-YDÇ', '325-STAR', '425-YAĞCILAR']

        # Ana SQL sorgusu - Girilen tarihteki Net Durum = 0 olanları hariç tut
        main_query = f"""
        SELECT
          KML.[FIRMA],
          KML.[VKN&TCKNO],
          KML.[CARİ GRUP],
          KML.[KOD YAPISI],
          ISNULL(
            COALESCE(
                (SELECT TOP 1 C.DEFINITION_ FROM LG_225_CLCARD C WITH (NOLOCK) WHERE (CASE WHEN C.ISPERSCOMP=1 THEN C.TCKNO ELSE C.TAXNR END) = KML.[VKN&TCKNO]),
                (SELECT TOP 1 C.DEFINITION_ FROM LG_325_CLCARD C WITH (NOLOCK) WHERE (CASE WHEN C.ISPERSCOMP=1 THEN C.TCKNO ELSE C.TAXNR END) = KML.[VKN&TCKNO]),
                (SELECT TOP 1 C.DEFINITION_ FROM LG_425_CLCARD C WITH (NOLOCK) WHERE (CASE WHEN C.ISPERSCOMP=1 THEN C.TCKNO ELSE C.TAXNR END) = KML.[VKN&TCKNO])
            ), ''
          ) AS CARI_UNVANI,
          SUM(KML.[USD_BORC]) [USD_BORC],
          SUM(KML.[EURO_BORC]) [EURO_BORC],
          SUM(KML.[TL_BORC]) [TL_BORC],
          (SUM(KML.[USD_BORC]*KML.USD_SATIS_KURU))+(SUM(KML.[EURO_BORC]*KML.EUR_SATIS_KURU))+SUM(KML.[TL_BORC]) AS TOPLAM_TL_BORC,
          SUM(KML.[USD_ALACAK]) [USD_ALACAK],
          SUM(KML.[EURO_ALACAK]) [EURO_ALACAK],
          SUM(KML.[TL_ALACAK]) [TL_ALACAK],
          (SUM(KML.[USD_ALACAK]*KML.USD_SATIS_KURU))+(SUM(KML.[EURO_ALACAK]*KML.EUR_SATIS_KURU))+SUM(KML.[TL_ALACAK]) AS TOPLAM_TL_ALACAK,
          KML.[USD_SATIS_KURU],
          KML.[EUR_SATIS_KURU]
        FROM (
          -- 225 Dataset
          SELECT
            '225-YDÇ' AS FIRMA,
            CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE TAXNR END AS [VKN&TCKNO],
            CL.SPECODE5 AS [CARİ GRUP],
            LEFT(CL.CODE, 3) AS [KOD YAPISI],

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_225_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=1 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0) AS USD_BORC,

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_225_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=20 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0) AS EURO_BORC,

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.AMOUNT ELSE 0 END)
                    FROM LG_225_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR IN (0,160) AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0) AS TL_BORC,

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_225_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=1 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0) AS USD_ALACAK,

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_225_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=20 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0) AS EURO_ALACAK,

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.AMOUNT ELSE 0 END)
                    FROM LG_225_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR IN (0,160) AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0) AS TL_ALACAK,

            ISNULL((SELECT TOP 1 RATES2 FROM LG_EXCHANGE_225 EX WITH (NOLOCK) WHERE EX.CRTYPE=1 AND CAST(EX.EDATE AS DATE) <= '{selected_date}' ORDER BY EX.EDATE DESC), 0) AS USD_SATIS_KURU,
            ISNULL((SELECT TOP 1 RATES2 FROM LG_EXCHANGE_225 EX WITH (NOLOCK) WHERE EX.CRTYPE=20 AND CAST(EX.EDATE AS DATE) <= '{selected_date}' ORDER BY EX.EDATE DESC), 0) AS EUR_SATIS_KURU

          FROM LG_225_CLCARD CL WITH (NOLOCK)
          WHERE CL.ACTIVE = 0 AND (CL.CODE LIKE '320%' OR CL.CODE LIKE '120%') 
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) IS NOT NULL 
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) != ''
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) != '0000000000'

          UNION ALL

          -- 325 Dataset
          SELECT
            '325-STAR' AS FIRMA,
            CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE TAXNR END,
            CL.SPECODE5,
            LEFT(CL.CODE, 3),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_325_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=1 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_325_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=20 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.AMOUNT ELSE 0 END)
                    FROM LG_325_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR IN (0,160) AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_325_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=1 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_325_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=20 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.AMOUNT ELSE 0 END)
                    FROM LG_325_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR IN (0,160) AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT TOP 1 RATES2 FROM LG_EXCHANGE_325 EX WITH (NOLOCK) WHERE EX.CRTYPE=1 AND CAST(EX.EDATE AS DATE) <= '{selected_date}' ORDER BY EX.EDATE DESC), 0),
            ISNULL((SELECT TOP 1 RATES2 FROM LG_EXCHANGE_325 EX WITH (NOLOCK) WHERE EX.CRTYPE=20 AND CAST(EX.EDATE AS DATE) <= '{selected_date}' ORDER BY EX.EDATE DESC), 0)

          FROM LG_325_CLCARD CL WITH (NOLOCK)
          WHERE CL.ACTIVE = 0 AND (CL.CODE LIKE '320%' OR CL.CODE LIKE '120%')
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) IS NOT NULL 
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) != ''
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) != '0000000000'

          UNION ALL

          -- 425 Dataset
          SELECT
            '425-YAĞCILAR' AS FIRMA,
            CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE TAXNR END,
            CL.SPECODE5,
            LEFT(CL.CODE, 3),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_425_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=1 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_425_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=20 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=0 THEN CLF.AMOUNT ELSE 0 END)
                    FROM LG_425_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR IN (0,160) AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=0 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_425_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=1 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.TRNET ELSE 0 END)
                    FROM LG_425_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR=20 AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT SUM(CASE WHEN CLF.SIGN=1 THEN CLF.AMOUNT ELSE 0 END)
                    FROM LG_425_01_CLFLINE CLF WITH (NOLOCK)
                    WHERE CLF.CANCELLED=0 AND CLF.PAIDINCASH=0 AND CLF.TRCURR IN (0,160) AND CLF.CLIENTREF=CL.LOGICALREF AND CLF.SIGN=1 AND CAST(CLF.DATE_ AS DATE) <= '{selected_date}'), 0),

            ISNULL((SELECT TOP 1 RATES2 FROM LG_EXCHANGE_425 EX WITH (NOLOCK) WHERE EX.CRTYPE=1 AND CAST(EX.EDATE AS DATE) <= '{selected_date}' ORDER BY EX.EDATE DESC), 0),
            ISNULL((SELECT TOP 1 RATES2 FROM LG_EXCHANGE_425 EX WITH (NOLOCK) WHERE EX.CRTYPE=20 AND CAST(EX.EDATE AS DATE) <= '{selected_date}' ORDER BY EX.EDATE DESC), 0)

          FROM LG_425_CLCARD CL WITH (NOLOCK)
          WHERE CL.ACTIVE = 0 AND (CL.CODE LIKE '320%' OR CL.CODE LIKE '120%')
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) IS NOT NULL 
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) != ''
            AND (CASE WHEN CL.ISPERSCOMP=1 THEN CL.TCKNO ELSE CL.TAXNR END) != '0000000000'

        ) KML
        WHERE 0=0
        """

        # Filtreleme koşullarını ekle
        where_conditions = []

        # Firma filtresi (multi-select) - değişiklik yok
        if firma_filter and len(firma_filter) > 0:
            firma_conditions = []
            for firma in firma_filter:
                if firma.strip():
                    safe_firma = firma.strip().replace("'", "''")  # SQL injection koruması
                    firma_conditions.append(f"KML.[FIRMA] = '{safe_firma}'")
            if firma_conditions:
                where_conditions.append(f"({' OR '.join(firma_conditions)})")

        # Cari Grup filtresi (multi-select) - GÜNCELLENMIŞ
        if cari_grup_filter and len(cari_grup_filter) > 0:
            if len(cari_grup_filter) == 1 and cari_grup_filter[0] == '__EMPTY_ONLY__':
                # Sadece boş değer seçili ise
                where_conditions.append("(KML.[CARİ GRUP] = '' OR KML.[CARİ GRUP] IS NULL)")
                print("DEBUG - Sadece boş grup filtresi eklendi")
            else:
                # Normal grup filtreleme
                grup_conditions = []
                for grup in cari_grup_filter:
                    if grup == '' or grup == '__EMPTY_ONLY__':  # Boş değer
                        grup_conditions.append("(KML.[CARİ GRUP] = '' OR KML.[CARİ GRUP] IS NULL)")
                    elif grup.strip():
                        safe_grup = grup.strip().replace("'", "''")  # SQL injection koruması
                        grup_conditions.append(f"KML.[CARİ GRUP] = '{safe_grup}'")
                if grup_conditions:
                    where_conditions.append(f"({' OR '.join(grup_conditions)})")
                    print(f"DEBUG - Grup filtresi eklendi: {grup_conditions}")

        # Cari Tür filtresi (multi-select) - GÜNCELLENMIŞ
        if cari_tur_filter and len(cari_tur_filter) > 0:
            if len(cari_tur_filter) == 1 and cari_tur_filter[0] == '__EMPTY_ONLY__':
                # Sadece boş değer seçili ise
                where_conditions.append("(KML.[KOD YAPISI] = '' OR KML.[KOD YAPISI] IS NULL)")
                print("DEBUG - Sadece boş tür filtresi eklendi")
            else:
                # Normal tür filtreleme
                tur_conditions = []
                for tur in cari_tur_filter:
                    if tur == '' or tur == '__EMPTY_ONLY__':  # Boş değer
                        tur_conditions.append("(KML.[KOD YAPISI] = '' OR KML.[KOD YAPISI] IS NULL)")
                    elif tur.strip():
                        safe_tur = tur.strip().replace("'", "''")  # SQL injection koruması
                        tur_conditions.append(f"KML.[KOD YAPISI] = '{safe_tur}'")
                if tur_conditions:
                    where_conditions.append(f"({' OR '.join(tur_conditions)})")
                    print(f"DEBUG - Tür filtresi eklendi: {tur_conditions}")

        # WHERE koşullarını ana sorguya ekle
        if where_conditions:
            main_query += f" AND {' AND '.join(where_conditions)}"

        # GROUP BY ekle
        main_query += """
        GROUP BY 
          KML.[FIRMA],
          KML.[VKN&TCKNO],
          KML.[CARİ GRUP],
          KML.[KOD YAPISI],
          KML.[USD_SATIS_KURU],
          KML.[EUR_SATIS_KURU]
        """

        # HAVING koşullarını birleştir
        having_conditions = []

        # ÖNEMLI: Girilen tarihteki Net Durum != 0 filtresi
        # Seçilen tarih itibariyle Net Durum sıfır olanları hariç tut
        having_conditions.append("""(
            (SUM(KML.[USD_BORC]*KML.USD_SATIS_KURU))+(SUM(KML.[EURO_BORC]*KML.EUR_SATIS_KURU))+SUM(KML.[TL_BORC])
        ) - (
            (SUM(KML.[USD_ALACAK]*KML.USD_SATIS_KURU))+(SUM(KML.[EURO_ALACAK]*KML.EUR_SATIS_KURU))+SUM(KML.[TL_ALACAK])
        ) != 0""")

        # Durum filtresi (borçlu/alacaklı) - Girilen tarihe göre
        if durum_filter and len(durum_filter) > 0:
            durum_conditions = []
            for durum in durum_filter:
                if durum == 'borclu':
                    durum_conditions.append("""(
                        (SUM(KML.[USD_BORC]*KML.USD_SATIS_KURU))+(SUM(KML.[EURO_BORC]*KML.EUR_SATIS_KURU))+SUM(KML.[TL_BORC]) >
                        (SUM(KML.[USD_ALACAK]*KML.USD_SATIS_KURU))+(SUM(KML.[EURO_ALACAK]*KML.EUR_SATIS_KURU))+SUM(KML.[TL_ALACAK])
                    )""")
                elif durum == 'alacakli':
                    durum_conditions.append("""(
                        (SUM(KML.[USD_BORC]*KML.USD_SATIS_KURU))+(SUM(KML.[EURO_BORC]*KML.EUR_SATIS_KURU))+SUM(KML.[TL_BORC]) <
                        (SUM(KML.[USD_ALACAK]*KML.USD_SATIS_KURU))+(SUM(KML.[EURO_ALACAK]*KML.EUR_SATIS_KURU))+SUM(KML.[TL_ALACAK])
                    )""")
            if durum_conditions:
                having_conditions.append(f"({' OR '.join(durum_conditions)})")

        # Cari arama filtresi
        if selected_cari and selected_cari.strip():
            cari_search = selected_cari.strip().replace("'", "''")  # SQL injection koruması
            having_conditions.append(f"""(
                ISNULL((SELECT TOP 1 C.DEFINITION_ FROM LG_225_CLCARD C WITH (NOLOCK) WHERE (CASE WHEN C.ISPERSCOMP=1 THEN C.TCKNO ELSE C.TAXNR END) = KML.[VKN&TCKNO]), '') LIKE '%{cari_search}%'
                OR
                ISNULL((SELECT TOP 1 C.DEFINITION_ FROM LG_325_CLCARD C WITH (NOLOCK) WHERE (CASE WHEN C.ISPERSCOMP=1 THEN C.TCKNO ELSE C.TAXNR END) = KML.[VKN&TCKNO]), '') LIKE '%{cari_search}%'
                OR
                ISNULL((SELECT TOP 1 C.DEFINITION_ FROM LG_425_CLCARD C WITH (NOLOCK) WHERE (CASE WHEN C.ISPERSCOMP=1 THEN C.TCKNO ELSE C.TAXNR END) = KML.[VKN&TCKNO]), '') LIKE '%{cari_search}%'
            )""")

        # HAVING koşullarını ekle
        if having_conditions:
            main_query += f" HAVING {' AND '.join(having_conditions)}"

        # Sorguyu çalıştır
        cursor.execute(main_query)
        columns = [column[0] for column in cursor.description]
        raw_results = []
        for row in cursor.fetchall():
            raw_results.append(dict(zip(columns, row)))

        # Sonuçları işle - TOPLAM_TL_BORC ve TOPLAM_TL_ALACAK zaten sorguda hesaplandı
        results = raw_results

        # Kur bilgilerini ilk kayıttan al (tüm kayıtlarda aynı olacak)
        usd_kuru = results[0]['USD_SATIS_KURU'] if results else 0
        eur_kuru = results[0]['EUR_SATIS_KURU'] if results else 0

        # Cari Grup listesi al (tüm firmalardan)
        cari_grup_list = []
        try:
            cari_grup_query = f"""
            SELECT DISTINCT CL.SPECODE5 AS [CARİ GRUP]
            FROM (
                SELECT SPECODE5 FROM LG_225_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%') AND SPECODE5 IS NOT NULL AND SPECODE5 != ''
                UNION
                SELECT SPECODE5 FROM LG_325_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%') AND SPECODE5 IS NOT NULL AND SPECODE5 != ''
                UNION
                SELECT SPECODE5 FROM LG_425_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%') AND SPECODE5 IS NOT NULL AND SPECODE5 != ''
            ) CL
            ORDER BY [CARİ GRUP]
            """
            cursor.execute(cari_grup_query)
            cari_grup_list = [row[0] for row in cursor.fetchall()]
        except Exception as e:
            print(f"Cari grup listesi alınırken hata: {e}")
            cari_grup_list = []

        # Cari Tür listesi al (KOD YAPISI - ilk 3 karakter)
        cari_tur_list = []
        try:
            cari_tur_query = f"""
            SELECT DISTINCT LEFT(CL.CODE, 3) AS [KOD YAPISI]
            FROM (
                SELECT CODE FROM LG_225_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%')
                UNION
                SELECT CODE FROM LG_325_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%')
                UNION
                SELECT CODE FROM LG_425_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%')
            ) CL
            ORDER BY [KOD YAPISI]
            """
            cursor.execute(cari_tur_query)
            cari_tur_list = [row[0] for row in cursor.fetchall()]
        except Exception as e:
            print(f"Cari tür listesi alınırken hata: {e}")
            cari_tur_list = []

        # Cari listesi al (tüm firmalardan)
        cari_list = []
        try:
            cari_list_query = f"""
            SELECT DISTINCT C.DEFINITION_ AS CARI_UNVANI
            FROM (
                SELECT DEFINITION_, CASE WHEN ISPERSCOMP=1 THEN TCKNO ELSE TAXNR END as VKN_TCKNO 
                FROM LG_225_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%') AND DEFINITION_ IS NOT NULL AND DEFINITION_ != ''
                UNION
                SELECT DEFINITION_, CASE WHEN ISPERSCOMP=1 THEN TCKNO ELSE TAXNR END 
                FROM LG_325_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%') AND DEFINITION_ IS NOT NULL AND DEFINITION_ != ''
                UNION
                SELECT DEFINITION_, CASE WHEN ISPERSCOMP=1 THEN TCKNO ELSE TAXNR END 
                FROM LG_425_CLCARD WHERE ACTIVE = 0 AND (CODE LIKE '320%' OR CODE LIKE '120%') AND DEFINITION_ IS NOT NULL AND DEFINITION_ != ''
            ) C
            ORDER BY CARI_UNVANI
            """
            cursor.execute(cari_list_query)
            cari_list = [row[0] for row in cursor.fetchall()]
        except Exception as e:
            print(f"Cari listesi alınırken hata: {e}")
            cari_list = []

        conn.close()

        return render_template('cari_bakiye.html',
                               results=results,
                               firma_list=firma_list,
                               cari_list=cari_list,
                               cari_grup_list=cari_grup_list,
                               cari_tur_list=cari_tur_list,
                               selected_date=selected_date,
                               selected_cari=selected_cari,
                               selected_firmas=selected_firmas,
                               selected_cari_grups=selected_cari_grups,
                               selected_cari_turs=selected_cari_turs,
                               selected_durums=selected_durums,
                               usd_kuru=usd_kuru,
                               eur_kuru=eur_kuru,
                               username=session.get('username'),
                               fullname=session.get('fullname'))

    except Exception as e:
        flash(f'Hata: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# cari_bakiye_api endpoint'indeki filtreleme mantığını da güncelleyin

@app.route('/cari_bakiye_api')
def cari_bakiye_api():
    """API endpoint for AJAX requests"""
    from datetime import datetime  # Import ekle
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        conn = get_db_connection2()
        cursor = conn.cursor()

        selected_date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))

        # Multi-select değerleri al
        selected_firmas = request.args.get('firmas', '')
        selected_cari_grups = request.args.get('cari_grups', '')
        selected_cari_turs = request.args.get('cari_turs', '')
        selected_durums = request.args.get('durums', '')

        print(f"API DEBUG - Gelen cari_grups parametresi: '{selected_cari_grups}'")
        print(f"API DEBUG - Gelen cari_turs parametresi: '{selected_cari_turs}'")

        # Liste haline getir ve temizle
        firma_filter = [f.strip() for f in selected_firmas.split(',') if f.strip()] if selected_firmas else []

        # Cari Grup için özel kontrol
        if selected_cari_grups == '__EMPTY_ONLY__':
            # Sadece boş gruplar için özel filtre
            cari_grup_filter = ['__EMPTY_ONLY__']
            print("API DEBUG - Sadece boş gruplar seçildi")
        else:
            cari_grup_filter = [g.strip() if g.strip() else '' for g in selected_cari_grups.split(',') if
                                g or g == ''] if selected_cari_grups else []

        # Cari Tür için özel kontrol
        if selected_cari_turs == '__EMPTY_ONLY__':
            # Sadece boş türler için özel filtre
            cari_tur_filter = ['__EMPTY_ONLY__']
            print("API DEBUG - Sadece boş türler seçildi")
        else:
            cari_tur_filter = [t.strip() if t.strip() else '' for t in selected_cari_turs.split(',') if
                               t or t == ''] if selected_cari_turs else []

        durum_filter = [d.strip() for d in selected_durums.split(',') if d.strip()] if selected_durums else []

        print(f"API DEBUG - İşlenmiş cari_grup_filter: {cari_grup_filter}")
        print(f"API DEBUG - İşlenmiş cari_tur_filter: {cari_tur_filter}")

        # Burada API endpoint'inize özgü sorgu mantığınızı ekleyin
        # Filtreleme mantığı ana endpoint ile aynı olmalı

        # Özet sorgusu devam eder...
        summary_query = f"""
        -- Mevcut summary_query kodunuz burada devam eder
        -- Filtreleme WHERE koşulları eklenecek
        """

        # WHERE koşulları ekleme mantığı ana endpoint ile aynı
        where_conditions = []

        # Cari Grup filtresi (API için)
        if cari_grup_filter and len(cari_grup_filter) > 0:
            if len(cari_grup_filter) == 1 and cari_grup_filter[0] == '__EMPTY_ONLY__':
                # Sadece boş değer seçili ise - API sorgusuna uygun alan adı kullanın
                where_conditions.append("(CL.SPECODE5 = '' OR CL.SPECODE5 IS NULL)")
                print("API DEBUG - Sadece boş grup filtresi eklendi")
            else:
                # Normal grup filtreleme
                grup_conditions = []
                for grup in cari_grup_filter:
                    if grup == '' or grup == '__EMPTY_ONLY__':
                        grup_conditions.append("(CL.SPECODE5 = '' OR CL.SPECODE5 IS NULL)")
                    elif grup.strip():
                        safe_grup = grup.strip().replace("'", "''")
                        grup_conditions.append(f"CL.SPECODE5 = '{safe_grup}'")
                if grup_conditions:
                    where_conditions.append(f"({' OR '.join(grup_conditions)})")

        # Cari Tür filtresi (API için)
        if cari_tur_filter and len(cari_tur_filter) > 0:
            if len(cari_tur_filter) == 1 and cari_tur_filter[0] == '__EMPTY_ONLY__':
                # Sadece boş değer seçili ise - API sorgusuna uygun alan adı kullanın
                where_conditions.append("(LEFT(CL.CODE, 3) = '' OR LEFT(CL.CODE, 3) IS NULL)")
                print("API DEBUG - Sadece boş tür filtresi eklendi")
            else:
                # Normal tür filtreleme
                tur_conditions = []
                for tur in cari_tur_filter:
                    if tur == '' or tur == '__EMPTY_ONLY__':
                        tur_conditions.append("(LEFT(CL.CODE, 3) = '' OR LEFT(CL.CODE, 3) IS NULL)")
                    elif tur.strip():
                        safe_tur = tur.strip().replace("'", "''")
                        tur_conditions.append(f"LEFT(CL.CODE, 3) = '{safe_tur}'")
                if tur_conditions:
                    where_conditions.append(f"({' OR '.join(tur_conditions)})")

        # WHERE koşullarını sorguya ekle
        if where_conditions:
            # summary_query'ye WHERE koşullarını ekle
            pass

        cursor.execute(summary_query)
        columns = [column[0] for column in cursor.description]
        summary_data = []
        for row in cursor.fetchall():
            summary_data.append(dict(zip(columns, row)))

        conn.close()

        return jsonify({
            'summary': summary_data,
            'success': True
        })

    except Exception as e:
        print(f"API ERROR: {str(e)}")
        return jsonify({'error': str(e)}), 500


# YDÇ Metal veri endpoint'i - Günlük ve Üretim kaldırıldı
@app.route('/get-ydc-data/<data_type>')
@login_required
def get_ydc_data(data_type):
    """YDÇ Metal verilerini getir - Günlük ve Üretim kaldırıldı"""
    try:
        data_functions = {
            'ydc_sevkiyat': get_ydc_sevkiyat_data,
            'ydc_satis': get_ydc_satis_data,
            'ydc_petrol': get_ydc_petrol_data,
            'ydc_lazer_planlama': get_ydc_lazer_planlama_data,
            'ydc_kaynakhane': get_ydc_kaynakhane_data,
            'ydc_kalite': get_ydc_kalite_data,
            'ydc_isg': get_ydc_isg_data,
            'ydc_insankaynaklari': get_ydc_insankaynaklari_data,
            'ydc_ihracat': get_ydc_ihracat_data,
            'ydc_lazer_gunduz': get_ydc_lazer_gunduz_data,
            'ydc_lazer_gece': get_ydc_lazer_gece_data,
            'ydc_depo': get_ydc_depo_data
        }

        if data_type in data_functions:
            data = data_functions[data_type]()
            return jsonify({
                'success': True,
                'data': data,
                'count': len(data) if data else 0
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Geçersiz veri tipi: {data_type}'
            }), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Sunucu hatası: {str(e)}'
        }), 500


# YDÇ Metal fonksiyonları - Günlük ve Üretim fonksiyonları kaldırıldı

def get_ydc_sevkiyat_data():
    """YDÇ Metal Sevkiyat verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[AD SOYAD]
              ,[OLUŞTURMA SAATİ]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
              ,[MİKTAR ( KG )]
              ,[MİKTAR ( ADET )]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_SEVKIYAT]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'OLUŞTURMA SAATİ', 'CARİ/PROJE', 'KONU', 'DETAY', 'MİKTAR (KG)',
                      'MİKTAR (ADET)']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_satis_data():
    """YDÇ Metal Satış verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_SATIS]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_petrol_data():
    """YDÇ Metal Petrol verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[AD SOYAD]
              ,[CARİ]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_PETROL]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_lazer_planlama_data():
    """YDÇ Metal Lazer Planlama verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_LAZER_PLANLAMA]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_kaynakhane_data():
    """YDÇ Metal Kaynakhane verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[SORUMLU]
              ,[OLUŞTURMA SAATİ]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
              ,[MİKTAR ( ADET )]
              ,[MİKTAR ( KG )]
              ,[SÜRE ( SAAT )]
              ,[YARINKİ HEDEF]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_KAYNAKHANE]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'SORUMLU', 'OLUŞTURMA SAATİ', 'CARİ/PROJE', 'KONU', 'DETAY', 'MİKTAR (ADET)',
                      'MİKTAR (KG)', 'SÜRE (SAAT)', 'YARINKİ HEDEF']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_kalite_data():
    """YDÇ Metal Kalite verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_KALITE]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_isg_data():
    """YDÇ Metal İSG verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_ISG]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_insankaynaklari_data():
    """YDÇ Metal İnsan Kaynakları verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
              ,[LOKASYON]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_INSANKAYNAKLARI]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY', 'LOKASYON']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_ihracat_data():
    """YDÇ Metal İhracat verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_IHRACAT]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_lazer_gunduz_data():
    """YDÇ Metal Lazer Gündüz verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ADI SOYADI]
              ,[OLUŞTURMA SAATİ]
              ,[VARDİYA]
              ,[CARİ/PROJE]
              ,[MAKİNE]
              ,[PERSONEL]
              ,[MİKTAR ( KG )]
              ,[SÜRE ( SAAT )]
              ,[KAYIP ( SAAT )]
              ,[DETAY]
              ,[YARINKİ HEDEF]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_GUNDUZ_LAZER]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'ADI SOYADI', 'OLUŞTURMA SAATİ', 'VARDİYA', 'CARİ/PROJE', 'MAKİNE', 'PERSONEL',
                      'MİKTAR (KG)', 'SÜRE (SAAT)', 'KAYIP (SAAT)', 'DETAY', 'YARINKİ HEDEF']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_lazer_gece_data():
    """YDÇ Metal Lazer Gece verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ADI SOYADI]
              ,[OLUŞTURMA SAATİ]
              ,[VARDİYA]
              ,[CARİ/PROJE]
              ,[MAKİNE]
              ,[PERSONEL]
              ,[MİKTAR ( KG )]
              ,[SÜRE ( SAAT )]
              ,[KAYIP ( SAAT )]
              ,[DETAY]
              ,[YARINKİ HEDEF]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_GECE_LAZER]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'ADI SOYADI', 'OLUŞTURMA SAATİ', 'VARDİYA', 'CARİ/PROJE', 'MAKİNE', 'PERSONEL',
                      'MİKTAR (KG)', 'SÜRE (SAAT)', 'KAYIP (SAAT)', 'DETAY', 'YARINKİ HEDEF']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_ydc_depo_data():
    """YDÇ Metal Depo verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_YDC_RAPOR_DEPO]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


# Star Yağcılar veri endpoint'leri
@app.route('/get-star-data/<data_type>')
@login_required
def get_star_data(data_type):
    """Star Yağcılar verilerini getir"""
    try:
        data_functions = {
            'star_uretim': get_star_uretim_data,
            'star_satinalma': get_star_satinalma_data,
            'star_proje': get_star_proje_data,
            'star_kalite': get_star_kalite_data,
            'star_insankaynaklari': get_star_insankaynaklari_data,
            'star_ihracat': get_star_ihracat_data,
            'star_depo': get_star_depo_data
        }

        if data_type in data_functions:
            data = data_functions[data_type]()
            return jsonify({
                'success': True,
                'data': data,
                'count': len(data) if data else 0
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Geçersiz veri tipi: {data_type}'
            }), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Sunucu hatası: {str(e)}'
        }), 500


# Star Yağcılar fonksiyonları

def get_star_uretim_data():
    """Star Yağcılar Üretim verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
              ,[SORUMLU]
              ,[MİKTAR ( KG )]
              ,[MİKTAR ( ADET )]
              ,[YARINKİ HEDEF]
        FROM [MikroDB_V16_10].[dbo].[_DT_STAR_RAPOR_URETIM]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY', 'SORUMLU', 'MİKTAR (KG)', 'MİKTAR (ADET)',
                      'YARINKİ HEDEF']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_star_satinalma_data():
    """Star Yağcılar Satın Alma verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_STAR_RAPOR_SATINALMA]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_star_proje_data():
    """Star Yağcılar Proje Ekibi verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[DETAY]
              ,[YARINKİ HEDEF]
        FROM [MikroDB_V16_10].[dbo].[_DT_STAR_RAPOR_PROJE]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'DETAY', 'YARINKİ HEDEF']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_star_kalite_data():
    """Star Yağcılar Kalite verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_STAR_RAPOR_KALITE]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_star_insankaynaklari_data():
    """Star Yağcılar İnsan Kaynakları verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
              ,[LOKASYON]
        FROM [MikroDB_V16_10].[dbo].[_DT_STAR_RAPOR_INSANKAYNAKLARI]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY', 'LOKASYON']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_star_ihracat_data():
    """Star Yağcılar İhracat verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_STAR_RAPOR_IHRACAT]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_star_depo_data():
    """Star Yağcılar Depo verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[ AD SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
        FROM [MikroDB_V16_10].[dbo].[_DT_STAR_RAPOR_DEPO]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


# Yağcılar Metal Endüstri veri endpoint'i
@app.route('/get-yagcilar-data/<data_type>')
@login_required
def get_yagcilar_data(data_type):
    """Yağcılar Metal Endüstri verilerini getir"""
    try:
        data_functions = {
            'yagcilar_satis': get_yagcilar_satis_data
        }

        if data_type in data_functions:
            data = data_functions[data_type]()
            return jsonify({
                'success': True,
                'data': data,
                'count': len(data) if data else 0
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Geçersiz veri tipi: {data_type}'
            }), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Sunucu hatası: {str(e)}'
        }), 500


def get_yagcilar_satis_data():
    """Yağcılar Metal Endüstri Satış verilerini getir"""
    try:
        conn = get_db_connection3()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[AD_SOYAD]
              ,[CARİ/PROJE]
              ,[KONU]
              ,[DETAY]
              ,[TUTAR (TL)]
        FROM [MikroDB_V16_10].[dbo].[_DT_YAGCILAR_RAPOR_SATIS]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY', 'TUTAR (TL)']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


# Genel sekmesi veri endpoint'i
@app.route('/get-genel-data/<data_type>')
@login_required
def get_genel_data(data_type):
    """Genel sekmesi verilerini getir"""
    try:
        data_functions = {
            'genel_lastik': get_genel_lastik_data,
            'genel_kantar': get_genel_kantar_data,
            'genel_pesin': get_genel_pesin_data,
            'genel_satis_ekibi': get_genel_satis_ekibi_data
        }

        if data_type in data_functions:
            data = data_functions[data_type]()
            return jsonify({
                'success': True,
                'data': data,
                'count': len(data) if data else 0
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Geçersiz veri tipi: {data_type}'
            }), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Sunucu hatası: {str(e)}'
        }), 500


def get_genel_lastik_data():
    """Genel - Lastik verilerini getir"""
    try:
        conn = get_db_connection5()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[TARİH]
              ,[FİŞ NO]
              ,[CARİ]
              ,[PLAKA]
              ,[YAPILAN İŞLEM]
              ,[ÖDEME]
              ,[TUTAR]
        FROM [YDCLASTIK].[dbo].[_DT_GUNLUK_ISLEMLER]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'TARİH', 'FİŞ NO', 'CARİ', 'PLAKA', 'YAPILAN İŞLEM', 'ÖDEME', 'TUTAR']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_genel_kantar_data():
    """Genel - Kantar verilerini getir"""
    try:
        conn = get_db_connection6()
        query = """
        SELECT TOP (1000) [SIRA]
              ,[Plaka]
              ,[ŞOFÖR]
              ,[CARİ ADI]
              ,[MALZEME]
              ,[1. TARTI]
              ,[2. TARTI]
              ,[TOPLAM KG]
              ,[ÜCRET]
        FROM [KantarDB].[dbo].[_BYT_GunlukKantar]
        ORDER BY [SIRA]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['SIRA', 'Plaka', 'ŞOFÖR', 'CARİ ADI', 'MALZEME', '1. TARTI', '2. TARTI', 'TOPLAM KG', 'ÜCRET']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_genel_pesin_data():
    """Genel - Peşin Kesilen Fatura verilerini getir"""
    try:
        conn = get_db_connection2()
        query = """
        SELECT TOP (1000) [Sıra]
              ,[Firma]
              ,[Fatura Türü]
              ,[Fatura Numarası]
              ,[ Fatura Tarihi]
              ,[Vade]
              ,[Cari Adı]
              ,[ Toplam Miktar]
              ,[İşlem Döviz Türü]
              ,[Tutar]
              ,[Sorumlu]
        FROM [TIGERDB].[dbo].[BYT_PESIN_FATURALAR]
        ORDER BY [Sıra]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['Sıra', 'Firma', 'Fatura Türü', 'Fatura Numarası', 'Fatura Tarihi', 'Vade', 'Cari Adı',
                      'Toplam Miktar', 'İşlem Döviz Türü', 'Tutar', 'Sorumlu']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


def get_genel_satis_ekibi_data():
    """Genel - Satış Ekibi Kesilen Faturalar verilerini getir"""
    try:
        conn = get_db_connection2()
        query = """
        SELECT TOP (1000) [CARİ HESAP ÜNVANI]
              ,[SİPARİŞ NUMARASI]
              ,[SİPARİŞ TUTAR]
              ,[İRSALİYE NUMARASI]
              ,[FATURA NUMARASI]
              ,[FATURA VE İRSALİYE TUTAR (TL))]
              ,[VADE]
              ,[TOPLAM MİKTAR]
              ,[BİRİM]
              ,[TOPLAM NET KG]
        FROM [TIGERDB].[dbo].[_DT_SATIS_GUNLUK_KESILEN_FATURA2]
        ORDER BY [CARİ HESAP ÜNVANI]
        """
        df = pd.read_sql(query, conn)
        conn.close()

        df.columns = ['CARİ HESAP ÜNVANI', 'SİPARİŞ NUMARASI', 'SİPARİŞ TUTAR', 'İRSALİYE NUMARASI',
                      'FATURA NUMARASI', 'FATURA VE İRSALİYE TUTAR (TL)', 'VADE', 'TOPLAM MİKTAR', 'BİRİM',
                      'TOPLAM NET KG']
        df = df.fillna('')
        df = df.replace([float('inf'), float('-inf')], '')

        return df.to_dict('records')
    except Exception as e:
        return []


# Tüm verileri tek seferde getiren endpoint
@app.route('/get-all-daily-reports')
@login_required
def get_all_daily_reports():
    """Tüm günlük rapor verilerini tek seferde getir"""
    try:
        all_data = {}

        # YDÇ Metal verileri
        ydc_functions = {
            'ydc_sevkiyat': get_ydc_sevkiyat_data,
            'ydc_satis': get_ydc_satis_data,
            'ydc_petrol': get_ydc_petrol_data,
            'ydc_lazer_planlama': get_ydc_lazer_planlama_data,
            'ydc_kaynakhane': get_ydc_kaynakhane_data,
            'ydc_kalite': get_ydc_kalite_data,
            'ydc_isg': get_ydc_isg_data,
            'ydc_insankaynaklari': get_ydc_insankaynaklari_data,
            'ydc_ihracat': get_ydc_ihracat_data,
            'ydc_lazer_gunduz': get_ydc_lazer_gunduz_data,
            'ydc_lazer_gece': get_ydc_lazer_gece_data,
            'ydc_depo': get_ydc_depo_data
        }

        # Star Yağcılar verileri
        star_functions = {
            'star_uretim': get_star_uretim_data,
            'star_satinalma': get_star_satinalma_data,
            'star_proje': get_star_proje_data,
            'star_kalite': get_star_kalite_data,
            'star_insankaynaklari': get_star_insankaynaklari_data,
            'star_ihracat': get_star_ihracat_data,
            'star_depo': get_star_depo_data
        }

        # Yağcılar Metal Endüstri verileri
        yagcilar_functions = {
            'yagcilar_satis': get_yagcilar_satis_data
        }

        # Genel veriler
        genel_functions = {
            'genel_lastik': get_genel_lastik_data,
            'genel_kantar': get_genel_kantar_data,
            'genel_pesin': get_genel_pesin_data,
            'genel_satis_ekibi': get_genel_satis_ekibi_data
        }

        # Tüm fonksiyonları çalıştır
        for key, func in ydc_functions.items():
            try:
                all_data[key] = func()
            except Exception as e:
                all_data[key] = []

        for key, func in star_functions.items():
            try:
                all_data[key] = func()
            except Exception as e:
                all_data[key] = []

        for key, func in yagcilar_functions.items():
            try:
                all_data[key] = func()
            except Exception as e:
                all_data[key] = []

        for key, func in genel_functions.items():
            try:
                all_data[key] = func()
            except Exception as e:
                all_data[key] = []

        return jsonify({
            'success': True,
            'data': all_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Sunucu hatası: {str(e)}'
        }), 500


@app.route('/send-daily-report-email', methods=['POST'])
@login_required
def send_daily_report_email():
    """Günlük rapor e-postası gönderme işlevi."""
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Content-Type application/json olmalı'
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Geçersiz JSON verisi'
            }), 400

        recipient = data.get('recipient', 'bayramyagci@yagcilar.com.tr')
        subject = data.get('subject', f'Günlük Raporlar - {datetime.now().strftime("%d.%m.%Y")}')
        user_message = data.get('message', '')
        active_tab = data.get('activeTab', '')
        active_sub_tab = data.get('activeSubTab', '')
        report_data = data.get('reportData', {})

        try:
            html_content = generate_email_html_content_updated(active_tab, active_sub_tab, report_data, user_message)
        except Exception as html_error:
            return jsonify({
                'success': False,
                'error': f'E-posta içeriği oluşturulurken hata oluştu: {str(html_error)}'
            }), 500

        if not recipient or '@' not in recipient:
            return jsonify({
                'success': False,
                'error': 'Geçerli bir e-posta adresi giriniz'
            }), 400

        sender_email = "yagcilarholding1@gmail.com"
        sender_password = "bqnp sius nztz padc"

        try:
            message = MIMEMultipart("alternative")
            message["From"] = sender_email
            message["To"] = recipient
            message["Subject"] = subject
            message["Date"] = formatdate(localtime=True)

            html_part = MIMEText(html_content, "html", "utf-8")
            message.attach(html_part)
        except Exception as msg_error:
            return jsonify({
                'success': False,
                'error': f'E-posta mesajı oluşturulurken hata oluştu: {str(msg_error)}'
            }), 500

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient, message.as_string())
        except smtplib.SMTPAuthenticationError:
            return jsonify({
                'success': False,
                'error': 'E-posta gönderme yetkilendirme hatası'
            }), 500
        except smtplib.SMTPException as smtp_error:
            return jsonify({
                'success': False,
                'error': f'E-posta gönderme hatası: {str(smtp_error)}'
            }), 500
        except Exception as send_error:
            return jsonify({
                'success': False,
                'error': f'E-posta gönderilirken hata oluştu: {str(send_error)}'
            }), 500

        try:
            log_user_action(session['user_id'], 'SEND_DAILY_REPORT_EMAIL',
                            f'Günlük rapor e-postası gönderildi: {recipient} - {active_tab}/{active_sub_tab}')
        except Exception as log_error:
            pass

        return jsonify({
            'success': True,
            'message': 'E-posta başarıyla gönderildi'
        })

    except Exception as e:
        try:
            if 'session' in globals() and 'user_id' in session:
                log_user_action(session['user_id'], 'SEND_DAILY_REPORT_EMAIL_ERROR',
                                f'E-posta gönderme hatası: {str(e)}')
        except Exception as log_error:
            pass

        return jsonify({
            'success': False,
            'error': f'E-posta gönderilirken beklenmeyen hata oluştu: {str(e)}'
        }), 500


@app.route('/gunluk-raporlar')
@login_required
@permission_required(menu_id=1027, permission_type='view')
def gunluk_raporlar():
    """Günlük raporlar sayfası."""
    user_id = session['user_id']
    menu_tree, menu_permissions = get_user_menu_permissions(user_id)

    return render_template('gunluk_raporlar.html',
                           username=session['username'],
                           fullname=session.get('fullname', ''),
                           menus=menu_tree,
                           permissions=menu_permissions,
                           is_admin=session.get('is_admin', False))


# Tablo oluşturma fonksiyonları - Debug'lar kaldırıldı

def generate_ydc_table_from_db(table_type):
    """Veritabanından YDÇ Metal verisiyle tablo oluştur"""
    try:
        data_functions = {
            'ydc_sevkiyat': get_ydc_sevkiyat_data,
            'ydc_satis': get_ydc_satis_data,
            'ydc_petrol': get_ydc_petrol_data,
            'ydc_lazer_planlama': get_ydc_lazer_planlama_data,
            'ydc_kaynakhane': get_ydc_kaynakhane_data,
            'ydc_kalite': get_ydc_kalite_data,
            'ydc_isg': get_ydc_isg_data,
            'ydc_insankaynaklari': get_ydc_insankaynaklari_data,
            'ydc_ihracat': get_ydc_ihracat_data,
            'ydc_lazer_gunduz': get_ydc_lazer_gunduz_data,
            'ydc_lazer_gece': get_ydc_lazer_gece_data,
            'ydc_depo': get_ydc_depo_data
        }

        headers_mapping = {
            'ydc_sevkiyat': ['SIRA', 'AD SOYAD', 'OLUŞTURMA SAATİ', 'CARİ/PROJE', 'KONU', 'DETAY', 'MİKTAR (KG)',
                             'MİKTAR (ADET)'],
            'ydc_satis': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY'],
            'ydc_petrol': ['SIRA', 'AD SOYAD', 'CARİ', 'KONU', 'DETAY'],
            'ydc_lazer_planlama': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY'],
            'ydc_kaynakhane': ['SIRA', 'SORUMLU', 'OLUŞTURMA SAATİ', 'CARİ/PROJE', 'KONU', 'DETAY', 'MİKTAR (ADET)',
                               'MİKTAR (KG)', 'SÜRE (SAAT)', 'YARINKİ HEDEF'],
            'ydc_kalite': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY'],
            'ydc_isg': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY'],
            'ydc_insankaynaklari': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY', 'LOKASYON'],
            'ydc_ihracat': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY'],
            'ydc_lazer_gunduz': ['SIRA', 'ADI SOYADI', 'OLUŞTURMA SAATİ', 'VARDİYA', 'CARİ/PROJE', 'MAKİNE', 'PERSONEL',
                                 'MİKTAR (KG)', 'SÜRE (SAAT)', 'KAYIP (SAAT)', 'DETAY', 'YARINKİ HEDEF'],
            'ydc_lazer_gece': ['SIRA', 'ADI SOYADI', 'OLUŞTURMA SAATİ', 'VARDİYA', 'CARİ/PROJE', 'MAKİNE', 'PERSONEL',
                               'MİKTAR (KG)', 'SÜRE (SAAT)', 'KAYIP (SAAT)', 'DETAY', 'YARINKİ HEDEF'],
            'ydc_depo': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        }

        if table_type in data_functions:
            data = data_functions[table_type]()
            headers = headers_mapping[table_type]

            if not data:
                return '<p>Veri bulunamadı.</p>'

            html = '<table class="report-table"><thead><tr>'

            for header in headers:
                html += f'<th>{header}</th>'
            html += '</tr></thead><tbody>'

            for row in data:
                html += '<tr>'
                for header in headers:
                    value = row.get(header, '-')
                    if value is None or value == '':
                        value = '-'
                    html += f'<td>{value}</td>'
                html += '</tr>'
            html += '</tbody></table>'

            return html
        else:
            return '<p>Geçersiz tablo tipi.</p>'

    except Exception as e:
        return f'<p>Tablo oluşturulurken hata oluştu: {str(e)}</p>'


def generate_star_table_from_db(table_type):
    """Veritabanından Star Yağcılar verisiyle tablo oluştur"""
    try:
        data_functions = {
            'star_uretim': get_star_uretim_data,
            'star_satinalma': get_star_satinalma_data,
            'star_proje': get_star_proje_data,
            'star_kalite': get_star_kalite_data,
            'star_insankaynaklari': get_star_insankaynaklari_data,
            'star_ihracat': get_star_ihracat_data,
            'star_depo': get_star_depo_data
        }

        headers_mapping = {
            'star_uretim': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY', 'SORUMLU', 'MİKTAR (KG)',
                            'MİKTAR (ADET)', 'YARINKİ HEDEF'],
            'star_satinalma': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY'],
            'star_proje': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'DETAY', 'YARINKİ HEDEF'],
            'star_kalite': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY'],
            'star_insankaynaklari': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY', 'LOKASYON'],
            'star_ihracat': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY'],
            'star_depo': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY']
        }

        if table_type in data_functions:
            data = data_functions[table_type]()
            headers = headers_mapping[table_type]

            if not data:
                return '<p>Veri bulunamadı.</p>'

            html = '<table class="report-table"><thead><tr>'

            for header in headers:
                html += f'<th>{header}</th>'
            html += '</tr></thead><tbody>'

            for row in data:
                html += '<tr>'
                for header in headers:
                    value = row.get(header, '-')
                    if value is None or value == '':
                        value = '-'
                    html += f'<td>{value}</td>'
                html += '</tr>'
            html += '</tbody></table>'

            return html
        else:
            return '<p>Geçersiz tablo tipi.</p>'

    except Exception as e:
        return f'<p>Tablo oluşturulurken hata oluştu: {str(e)}</p>'


def generate_yagcilar_table_from_db(table_type):
    """Veritabanından Yağcılar Metal Endüstri verisiyle tablo oluştur"""
    try:
        data_functions = {
            'yagcilar_satis': get_yagcilar_satis_data
        }

        headers_mapping = {
            'yagcilar_satis': ['SIRA', 'AD SOYAD', 'CARİ/PROJE', 'KONU', 'DETAY', 'TUTAR (TL)']
        }

        if table_type in data_functions:
            data = data_functions[table_type]()
            headers = headers_mapping[table_type]

            if not data:
                return '<p>Veri bulunamadı.</p>'

            html = '<table class="report-table"><thead><tr>'

            for header in headers:
                html += f'<th>{header}</th>'
            html += '</tr></thead><tbody>'

            for row in data:
                html += '<tr>'
                for header in headers:
                    value = row.get(header, '-')
                    if value is None or value == '':
                        value = '-'
                    html += f'<td>{value}</td>'
                html += '</tr>'
            html += '</tbody></table>'

            return html
        else:
            return '<p>Geçersiz tablo tipi.</p>'

    except Exception as e:
        return f'<p>Tablo oluşturulurken hata oluştu: {str(e)}</p>'


def generate_genel_table_from_db(table_type):
    """Veritabanından Genel sekmesi verisiyle tablo oluştur"""
    try:
        data_functions = {
            'genel_lastik': get_genel_lastik_data,
            'genel_kantar': get_genel_kantar_data,
            'genel_pesin': get_genel_pesin_data,
            'genel_satis_ekibi': get_genel_satis_ekibi_data
        }

        headers_mapping = {
            'genel_lastik': ['SIRA', 'TARİH', 'FİŞ NO', 'CARİ', 'PLAKA', 'YAPILAN İŞLEM', 'ÖDEME', 'TUTAR'],
            'genel_kantar': ['SIRA', 'Plaka', 'ŞOFÖR', 'CARİ ADI', 'MALZEME', '1. TARTI', '2. TARTI', 'TOPLAM KG',
                             'ÜCRET'],
            'genel_pesin': ['Sıra', 'Firma', 'Fatura Türü', 'Fatura Numarası', 'Fatura Tarihi', 'Vade', 'Cari Adı',
                            'Toplam Miktar', 'İşlem Döviz Türü', 'Tutar', 'Sorumlu'],
            'genel_satis_ekibi': ['CARİ HESAP ÜNVANI', 'SİPARİŞ NUMARASI', 'SİPARİŞ TUTAR', 'İRSALİYE NUMARASI',
                                  'FATURA NUMARASI', 'FATURA VE İRSALİYE TUTAR (TL)', 'VADE', 'TOPLAM MİKTAR', 'BİRİM',
                                  'TOPLAM NET KG']
        }

        if table_type in data_functions:
            data = data_functions[table_type]()
            headers = headers_mapping[table_type]

            if not data:
                return '<p>Veri bulunamadı.</p>'

            html = '<table class="report-table"><thead><tr>'

            for header in headers:
                html += f'<th>{header}</th>'
            html += '</tr></thead><tbody>'

            for row in data:
                html += '<tr>'
                for header in headers:
                    value = row.get(header, '-')
                    if value is None or value == '':
                        value = '-'
                    html += f'<td>{value}</td>'
                html += '</tr>'
            html += '</tbody></table>'

            return html
        else:
            return '<p>Geçersiz tablo tipi.</p>'

    except Exception as e:
        return f'<p>Tablo oluşturulurken hata oluştu: {str(e)}</p>'


def generate_email_html_content_updated(active_tab, active_sub_tab, report_data, user_message):
    """E-posta için HTML içeriği oluştur - Hiyerarşik sekme yapısı ile"""
    try:
        now = datetime.now()
        date_str = now.strftime("%d.%m.%Y")
        time_str = now.strftime("%H:%M")

        sender_name = "Sistem"
        try:
            if 'fullname' in session and session['fullname']:
                sender_name = session['fullname']
            elif 'username' in session and session['username']:
                sender_name = session['username']
        except:
            sender_name = "Sistem"

        user_message_section = ""
        if user_message and user_message.strip():
            user_message_section = f"""
            <div class="user-message">
                <strong>💬 Ek Mesaj:</strong><br>
                {user_message}
            </div>
            """


        main_tab = ""
        if active_tab:
            if 'Star' in active_tab:
                main_tab = "star"
            elif 'Yağcılar Metal' in active_tab:
                main_tab = "yagcilar"
            elif 'Genel' in active_tab:
                main_tab = "genel"
            elif 'Ydç Metal' in active_tab:
                main_tab = "ydc"

        default_sub_tabs = {
            'ydc': 'sevkiyat',
            'star': 'uretim',
            'yagcilar': 'satis',
            'genel': 'kantar'
        }

        sub_tab = ""
        if main_tab:
            sub_tab = default_sub_tabs.get(main_tab, '')
        if active_sub_tab and main_tab:
            if 'Sevkiyat' in active_sub_tab:
                sub_tab = 'sevkiyat'
            elif 'Satış' in active_sub_tab or 'Satis' in active_sub_tab:
                sub_tab = 'satis'
            elif 'Petrol' in active_sub_tab:
                sub_tab = 'petrol'
            elif 'Lazer Planlama' in active_sub_tab:
                sub_tab = 'lazer-planlama'
            elif 'Kaynakhane' in active_sub_tab:
                sub_tab = 'kaynakhane'
            elif 'Kalite' in active_sub_tab:
                sub_tab = 'kalite'
            elif 'İSG' in active_sub_tab or 'ISG' in active_sub_tab:
                sub_tab = 'isg'
            elif 'İnsan Kaynakları' in active_sub_tab or 'Insan Kaynaklari' in active_sub_tab:
                sub_tab = 'ik'
            elif 'İhracat' in active_sub_tab or 'Ihracat' in active_sub_tab:
                sub_tab = 'ihracat'
            elif 'Lazer Gündüz' in active_sub_tab:
                sub_tab = 'lazer-gunduz'
            elif 'Lazer Gece' in active_sub_tab:
                sub_tab = 'lazer-gece'
            elif 'Depo' in active_sub_tab:
                sub_tab = 'depo'
            elif 'Üretim' in active_sub_tab or 'Uretim' in active_sub_tab:
                sub_tab = 'uretim'
            elif 'Satın Alma' in active_sub_tab:
                sub_tab = 'satinalma'
            elif 'Proje' in active_sub_tab:
                sub_tab = 'proje'
            elif 'Kantar' in active_sub_tab:
                sub_tab = 'kantar'
            elif 'Lastik' in active_sub_tab:
                sub_tab = 'lastik'
            elif 'Peşin' in active_sub_tab or 'Pesin' in active_sub_tab:
                sub_tab = 'pesin'
            elif 'Satış Ekibi' in active_sub_tab:
                sub_tab = 'satis-ekibi'

        def load_all_data():
            all_data = {}

            ydc_data_map = {
                'sevkiyat': 'ydc_sevkiyat',
                'satis': 'ydc_satis',
                'petrol': 'ydc_petrol',
                'lazer-planlama': 'ydc_lazer_planlama',
                'kaynakhane': 'ydc_kaynakhane',
                'kalite': 'ydc_kalite',
                'isg': 'ydc_isg',
                'ik': 'ydc_insankaynaklari',
                'ihracat': 'ydc_ihracat',
                'lazer-gunduz': 'ydc_lazer_gunduz',
                'lazer-gece': 'ydc_lazer_gece',
                'depo': 'ydc_depo'
            }

            for sub_key, db_key in ydc_data_map.items():
                try:
                    data = generate_ydc_table_from_db(db_key)
                    all_data[f'ydc-{sub_key}'] = data
                except Exception as e:
                    all_data[f'ydc-{sub_key}'] = f'<p class="text-center text-danger">Veri yüklenemedi: {str(e)}</p>'

            star_data_map = {
                'uretim': 'star_uretim',
                'satinalma': 'star_satinalma',
                'proje': 'star_proje',
                'kalite': 'star_kalite',
                'ik': 'star_insankaynaklari',
                'ihracat': 'star_ihracat',
                'depo': 'star_depo'
            }

            for sub_key, db_key in star_data_map.items():
                try:
                    data = generate_star_table_from_db(db_key)
                    all_data[f'star-{sub_key}'] = data
                except Exception as e:
                    all_data[f'star-{sub_key}'] = f'<p class="text-center text-danger">Veri yüklenemedi: {str(e)}</p>'

            yagcilar_data_map = {
                'satis': 'yagcilar_satis'
            }

            for sub_key, db_key in yagcilar_data_map.items():
                try:
                    data = generate_yagcilar_table_from_db(db_key)
                    all_data[f'yagcilar-{sub_key}'] = data
                except Exception as e:
                    all_data[
                        f'yagcilar-{sub_key}'] = f'<p class="text-center text-danger">Veri yüklenemedi: {str(e)}</p>'

            genel_data_map = {
                'kantar': 'genel_kantar',
                'lastik': 'genel_lastik',
                'pesin': 'genel_pesin',
                'satis-ekibi': 'genel_satis_ekibi'
            }

            for sub_key, db_key in genel_data_map.items():
                try:
                    data = generate_genel_table_from_db(db_key)
                    all_data[f'genel-{sub_key}'] = data
                except Exception as e:
                    all_data[f'genel-{sub_key}'] = f'<p class="text-center text-danger">Veri yüklenemedi: {str(e)}</p>'

            return all_data

        all_loaded_data = load_all_data()

        sub_tab_info = {
            'ydc': {
                'sevkiyat': {'title': '🚚 Sevkiyat'},
                'satis': {'title': '📊 Satış'},
                'petrol': {'title': '⛽ Petrol'},
                'lazer-planlama': {'title': '📐 Lazer Planlama'},
                'kaynakhane': {'title': '🔥 Kaynakhane'},
                'kalite': {'title': '✅ Kalite'},
                'isg': {'title': '🦺 İSG'},
                'ik': {'title': '👥 İnsan Kaynakları'},
                'ihracat': {'title': '📦 İhracat'},
                'lazer-gunduz': {'title': '☀️ Lazer Gündüz'},
                'lazer-gece': {'title': '🌙 Lazer Gece'},
                'depo': {'title': '🏪 Depo'}
            },
            'star': {
                'uretim': {'title': '🏭 Üretim'},
                'satinalma': {'title': '🛒 Satın Alma'},
                'proje': {'title': '📋 Proje Ekibi'},
                'kalite': {'title': '✅ Kalite'},
                'ik': {'title': '👥 İnsan Kaynakları'},
                'ihracat': {'title': '📦 İhracat'},
                'depo': {'title': '🏪 Depo'}
            },
            'yagcilar': {
                'satis': {'title': '📊 Satış'}
            },
            'genel': {
                'kantar': {'title': '⚖️ Kantar'},
                'lastik': {'title': '🛞 Lastik'},
                'pesin': {'title': '💵 Peşin Kesilen Fatura'},
                'satis-ekibi': {'title': '👨‍💼 Satış Ekibi Kesilen Faturalar'}
            }
        }

        def generate_sub_tab_buttons_for_group(tab_group, current_sub, all_data, sub_info):
            buttons_html = ""
            for sub_key, sub_details in sub_info[tab_group].items():
                is_active_main_tab = (tab_group == main_tab and main_tab != "")
                is_active_sub_tab = (sub_key == current_sub)
                checked = 'checked="checked"' if (is_active_main_tab and is_active_sub_tab) else ""

                clean_title = sub_details['title'].replace('🚚 ', '').replace('📊 ', '').replace('⛽ ', '').replace('📐 ',
                                                                                                                 '').replace(
                    '🔥 ', '').replace('✅ ', '').replace('🦺 ', '').replace('👥 ', '').replace('📦 ', '').replace('☀️ ',
                                                                                                              '').replace(
                    '🌙 ', '').replace('🏪 ', '').replace('🏭 ', '').replace('🛒 ', '').replace('📋 ', '').replace('🕘 ',
                                                                                                              '').replace(
                    '👷 ', '').replace('⚖️ ', '').replace('🛞 ', '').replace('💵 ', '').replace('👨‍💼 ', '')

                data_key = f'{tab_group}-{sub_key}'
                table_data = all_data.get(data_key, '<p class="text-center text-muted">Veri bulunamadı</p>')

                buttons_html += f"""
                <input type="checkbox" id="{tab_group}-{sub_key}" {checked}>
                <label for="{tab_group}-{sub_key}">{clean_title}</label>
                <div class="sub-content">
                    <div class="content-area">
                        <h4>{sub_details['title']}</h4>
                        {table_data}
                    </div>
                </div>
                """
            return buttons_html

        ydc_sub_tabs = generate_sub_tab_buttons_for_group('ydc', sub_tab if main_tab == 'ydc' else '', all_loaded_data,
                                                          sub_tab_info)
        star_sub_tabs = generate_sub_tab_buttons_for_group('star', sub_tab if main_tab == 'star' else '',
                                                           all_loaded_data, sub_tab_info)
        yagcilar_sub_tabs = generate_sub_tab_buttons_for_group('yagcilar', sub_tab if main_tab == 'yagcilar' else '',
                                                               all_loaded_data, sub_tab_info)
        genel_sub_tabs = generate_sub_tab_buttons_for_group('genel', sub_tab if main_tab == 'genel' else '',
                                                            all_loaded_data, sub_tab_info)

        html_template = f"""
        <!DOCTYPE html>
        <html lang="tr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Günlük Raporlar - Yağcılar Holding</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                }}
                .header {{
                    background-color: #282965;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 8px 8px 0 0;
                }}
                .content {{
                    background-color: white;
                    padding: 20px;
                    border-radius: 0 0 8px 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .user-message {{
                    background-color: #d4edda;
                    border: 1px solid #c3e6cb;
                    color: #155724;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .current-report {{
                    background-color: #e3f2fd;
                    border: 2px solid #2196f3;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 30px;
                }}
                .current-report h3 {{
                    color: #1976d2;
                    margin-top: 0;
                }}

                .main-tabs {{
                    border-bottom: 2px solid #282965;
                    margin-bottom: 20px;
                }}

                .main-tabs input[type="checkbox"] {{
                    display: none;
                }}

                .main-tabs input[type="checkbox"] + label {{
                    display: inline-block;
                    padding: 12px 20px;
                    margin-right: 10px;
                    background-color: #f8f9fa;
                    border: 1px solid #ddd;
                    border-bottom: 3px solid transparent;
                    cursor: pointer;
                    color: #282965;
                    font-weight: 600;
                    border-radius: 8px 8px 0 0;
                }}

                .main-tabs input[type="checkbox"] + label:hover {{
                    background-color: #e9ecef;
                    border-bottom-color: #6c757d;
                }}

                .main-tabs input[type="checkbox"]:checked + label {{
                    background-color: transparent;
                    color: #282965;
                    border-bottom-color: #282965;
                    font-weight: bold;
                }}

                .main-tab-content {{
                    display: none;
                    background-color: #fff;
                    border-radius: 0 0 8px 8px;
                    padding: 20px;
                    margin-top: 20px;
                }}

                .main-tabs input[type="checkbox"]:checked + label + .main-tab-content {{
                    display: block;
                }}

                .sub-tabs {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 10px;
                    margin-bottom: 20px;
                    display: flex;
                    flex-wrap: wrap;
                    gap: 5px;
                }}

                .sub-tabs input[type="checkbox"] {{
                    display: none;
                }}

                .sub-tabs input[type="checkbox"] + label {{
                    display: inline-block;
                    padding: 8px 15px;
                    background-color: #fff;
                    border: 1px solid #dee2e6;
                    border-radius: 5px;
                    cursor: pointer;
                    color: #6c757d;
                    font-weight: 500;
                    font-size: 14px;
                }}

                .sub-tabs input[type="checkbox"] + label:hover {{
                    background-color: #f8f9fa;
                    border-color: #6c757d;
                }}

                .sub-tabs input[type="checkbox"]:checked + label {{
                    background-color: #282965;
                    color: white;
                    border-color: #282965;
                }}

                .sub-content {{
                    display: none;
                    margin-top: 20px;
                }}

                .sub-tabs input[type="checkbox"]:checked + label + .sub-content {{
                    display: block;
                }}

                .content-area {{
                    background-color: #fff;
                    border-radius: 8px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    border-left: 4px solid #282965;
                }}

                .report-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                    font-size: 12px;
                }}
                .report-table th {{
                    background-color: #282965;
                    color: white;
                    padding: 8px 6px;
                    text-align: left;
                    border: 1px solid #ddd;
                    font-size: 11px;
                    word-wrap: break-word;
                }}
                .report-table td {{
                    padding: 6px 4px;
                    border: 1px solid #ddd;
                    background-color: #f9f9f9;
                    font-size: 11px;
                    word-wrap: break-word;
                }}
                .report-table tr:nth-child(even) td {{
                    background-color: #f1f1f1;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    padding: 20px;
                    color: #6c757d;
                    font-size: 14px;
                }}
                .badge {{
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                }}
                .badge.bg-success {{
                    background-color: #28a745;
                    color: white;
                }}
                .badge.bg-warning {{
                    background-color: #ffc107;
                    color: black;
                }}
                .badge.bg-danger {{
                    background-color: #dc3545;
                    color: white;
                }}
                .active-tab-info {{
                    background-color: #d1ecf1;
                    color: #0c5460;
                    padding: 10px 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                    text-align: center;
                    border: 1px solid #bee5eb;
                }}

                .default-message {{
                    text-align: center;
                    color: #6c757d;
                    font-style: italic;
                    margin-top: 20px;
                    padding: 30px;
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    border: 2px dashed #dee2e6;
                    display: {'block' if not main_tab else 'none'};
                }}

                .main-tabs input[type="checkbox"]:checked ~ .default-message {{
                    display: none;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Günlük Raporlar</h1>
                <p>Yağcılar Holding - {date_str}</p>
            </div>

            <div class="content">
                {user_message_section}

                <div class="tab-container">
                    <div class="main-tabs">
                        <input type="checkbox" id="main-ydc" {('checked="checked"' if main_tab == 'ydc' and main_tab != '' else '')}>
                        <label for="main-ydc">🏭 Ydç Metal</label>
                        <div class="main-tab-content">
                            <div class="sub-tabs">
                                {ydc_sub_tabs}
                            </div>
                        </div>

                        <input type="checkbox" id="main-star" {('checked="checked"' if main_tab == 'star' and main_tab != '' else '')}>
                        <label for="main-star">⭐ Star Yağcılar</label>
                        <div class="main-tab-content">
                            <div class="sub-tabs">
                                {star_sub_tabs}
                            </div>
                        </div>

                        <input type="checkbox" id="main-yagcilar" {('checked="checked"' if main_tab == 'yagcilar' and main_tab != '' else '')}>
                        <label for="main-yagcilar">⚙️ Yağcılar Metal Endüstri</label>
                        <div class="main-tab-content">
                            <div class="sub-tabs">
                                {yagcilar_sub_tabs}
                            </div>
                        </div>

                        <input type="checkbox" id="main-genel" {('checked="checked"' if main_tab == 'genel' and main_tab != '' else '')}>
                        <label for="main-genel">🏢 Genel</label>
                        <div class="main-tab-content">
                            <div class="sub-tabs">
                                {genel_sub_tabs}
                            </div>
                        </div>

                        <div class="default-message">
                            <h4 style="color: #6c757d; margin-bottom: 10px;">📊 Rapor Seçimi</h4>
                            <p>Yukarıdaki ana sekmelerden birini seçerek başlayın. Ardından alt sekmeleri görüntüleyebilirsiniz.</p>
                            <p><strong>🔄 Toggle:</strong> Aynı sekmeye tekrar tıklayarak kapatabilirsiniz (CSS-only).</p>
                            <div style="background-color: #d1ecf1; color: #0c5460; padding: 10px; border-radius: 5px; margin-top: 15px;">
                                <small><strong>🎯 Gönderilen Rapor:</strong> "{active_tab if active_tab else 'Genel'} → {active_sub_tab if active_sub_tab else 'Tümü'}" başlığında gönderildi</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="footer">
                <p>Bu e-posta Yağcılar Holding Günlük Raporlar sistemi tarafından otomatik olarak oluşturulmuştur.</p>
                <p>📅 Tarih: {date_str} {time_str}</p>
            </div>
        </body>
        </html>
        """

        return html_template

    except Exception as e:
        raise

if __name__ == '__main__':
    # Create required directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('templates/admin', exist_ok=True)
    os.makedirs('templates/admin/users', exist_ok=True)
    os.makedirs('templates/admin/roles', exist_ok=True)
    os.makedirs('templates/admin/menus', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    # Bu kontrol, kodun yalnızca ana işlemde çalıştığından emin olur, yeniden yükleyici işleminde değil
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        print(f"[INFO] Ana işlem algılandı (PID: {_process_id}). Zamanlayıcı başlatılıyor.")
        scheduler = create_scheduler()
        if scheduler:
            add_daily_mail_job()
            start_scheduler()
            # Uygulama çıktığında zamanlayıcıyı düzgünce kapat
            atexit.register(lambda: stop_scheduler())
    else:
        print(f"[INFO] Yeniden yükleyici işlem algılandı (PID: {_process_id}). Zamanlayıcı başlatma atlanıyor.")

    # Run the app with host set to allow external connections
    # and port set to 2025
    app.run(host='0.0.0.0', port=2025, debug=True)
    # Note: In production, you should set debug=False




