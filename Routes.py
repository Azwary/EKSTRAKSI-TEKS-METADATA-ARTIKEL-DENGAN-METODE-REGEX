import os
from functools import wraps
from flask import Blueprint, render_template, request, redirect, session, url_for, flash, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from model.regex import extract_text_from_pdf, clean, extract_metadata
from database import Error, create_connection, save_metadata, get_all_metadata, get_all_users, get_total_articles, get_total_users, get_roles, get_all_users

# Define the UPLOAD_FOLDER
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
PDF_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

routes = Blueprint('routes', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Anda belum login", "error")
            return redirect(url_for('routes.login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash("Anda tidak memiliki akses ke halaman ini.", "error")
                return render_template("layouts/error.html", message="Anda tidak memiliki akses ke halaman ini.")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@routes.route("/")
def home():
    return render_template("auth/login.html")

@routes.route("/notif")
def error():
    return render_template("layouts/notifikasi.html")

@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Password dan konfirmasi password tidak cocok", "error")
            return redirect(url_for('routes.register'))

        hashed_password = generate_password_hash(password)

        connection = create_connection()
        if connection is None:
            return "Database connection failed", 500

        try:
            cursor = connection.cursor()
            query = "INSERT INTO users (username, password, role) VALUES (%s, %s, 'Editor')"
            cursor.execute(query, (username, hashed_password))
            connection.commit()
            flash("Registrasi berhasil! Silakan login.", "success")
            return redirect(url_for('routes.login'))  
        except Exception as e:
            print(f"Error: {e}")
            flash("Gagal mendaftar pengguna", "error")
            return redirect(url_for('routes.register'))
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    return render_template('auth/register.html')  

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = get_user_by_username(username)
        if user:
            if check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                last_url = session.get('last_url', 'dashboard') 
                return redirect(last_url)

        flash("Username atau password salah", "error")
    return render_template('auth/login.html')


def get_user_by_username(username):
    connection = create_connection()
    if connection is None:
        return None

    try:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def update_user_password(user_id, new_password):
    """Fungsi untuk memperbarui password pengguna di database."""
    connection = create_connection()
    if connection is None:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor()
        query = "UPDATE users SET password = %s WHERE id = %s"
        cursor.execute(query, (new_password, user_id))
        connection.commit()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@routes.route("/dashboard")
@login_required
def dashboard():
    return render_template("layouts/index.html")

@routes.route('/total-articles', methods=['GET'])
@login_required
def total_articles():
    total = get_total_articles()
    return jsonify({"total": total})

@routes.route('/total-users', methods=['GET'])
@login_required
def total_users():
    total = get_total_users()
    return jsonify({"total": total})

@routes.route('/articles', methods=['GET'])
@login_required
def articles():
    metadata = get_all_metadata()
    return render_template('layouts/articles.html', articles=metadata)

@routes.route('/upload', methods=['GET', 'POST'])
@login_required
@role_required('Editor')
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)  
            text = extract_text_from_pdf(file_path)
            cleaned_text = clean(text) 
            metadata = extract_metadata(cleaned_text)  
            # save_metadata(metadata)  # Save metadata to the database
            return render_template('layouts/result.html', metadata=metadata, filename=filename, file_path=file_path)
    return render_template('layouts/upload.html')

@routes.route("/download/<filename>")
def download_file(filename):
    filename = secure_filename(filename)  # Amankan nama file
    file_path = os.path.join(PDF_FOLDER, filename)

    if not os.path.exists(file_path):
        abort(404, description="File tidak ditemukan")

    return send_from_directory(PDF_FOLDER, filename, as_attachment=True)

@routes.route('/results', methods=['POST'])
@login_required
@role_required('Editor')
def results():
    action = request.form.get('action')

    if action == 'edit':
        metadata = {
            "title": request.form.get("title"),
            "authors": request.form.get("authors"),
            "affiliations": request.form.get("affiliations"),
            "abstract": request.form.get("abstract"),
            "abstractEN": request.form.get("abstractEN"),
            "filename": request.form.get("filename"),
            "file_path": request.form.get("file_path"),
        }
        return render_template('layouts/edit.html', metadata=metadata)

    elif action == 'save':
        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()
                sql = """INSERT INTO articles (title, authors, affiliations, abstract, abstractEN, filename, file_path)
                         VALUES (%s, %s, %s, %s, %s, %s, %s)"""
                values = (
                    request.form.get("title"),
                    request.form.get("authors"),
                    request.form.get("affiliations"),
                    request.form.get("abstract"),
                    request.form.get("abstractEN"),
                    request.form.get("filename"),
                    request.form.get("file_path"),
                )
                cursor.execute(sql, values)
                connection.commit()
                cursor.close()
                connection.close()
                flash('Metadata berhasil disimpan!', 'success')
            except Error as e:
                flash(f'Gagal menyimpan metadata: {e}', 'danger')
                print(f"Error: {e}")
        else:
            flash('Koneksi ke database gagal!', 'danger')

    return redirect(url_for('routes.articles'))


@routes.route('/edit', methods=['GET', 'POST'])
@login_required
@role_required('Editor')
def edit_metadata():
    if request.method == 'POST':
        metadata = {
            "title": request.form.get("title"),
            "authors": request.form.get("authors"),
            "affiliations": request.form.get("affiliations"),
            "abstract": request.form.get("abstract"),
            "abstractEN": request.form.get("abstractEN"),
            "filename": request.form.get("filename"),
            "file_path": request.form.get("file_path"),
        }
        return render_template('layouts/edit.html', metadata=metadata)
    
    # Jika pengguna akses /edit langsung tanpa data
    return "Tidak ada data untuk diedit", 400

@routes.route('/save', methods=['POST'])
@login_required
@role_required('Editor')
def save_metadata():
    try:
        connection = create_connection()
        if connection:
            cursor = connection.cursor()
            sql = """INSERT INTO articles (title, authors, affiliations, abstract, abstractEN, filename, file_path)
                     VALUES (%s, %s, %s, %s, %s, %s, %s)"""
            values = (
                request.form.get("title"),
                request.form.get("authors"),
                request.form.get("affiliations"),
                request.form.get("abstract"),
                request.form.get("abstractEN"),
                request.form.get("filename"),
                request.form.get("file_path"),
            )
            cursor.execute(sql, values)
            connection.commit()
            cursor.close()
            connection.close()
            flash('Metadata berhasil disimpan!', 'success')
        else:
            flash('Koneksi ke database gagal!', 'danger')
    except Error as e:
        flash(f'Gagal menyimpan metadata: {e}', 'danger')
        print(f"Error: {e}")

    return redirect(url_for('routes.articles'))


@routes.route('/edit/<int:article_id>', methods=['GET'])
@login_required
def edit_article(article_id):
    """Menampilkan halaman edit artikel berdasarkan ID."""
    connection = create_connection()
    if connection is None:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM articles WHERE id = %s", (article_id,))
        article = cursor.fetchone()
        return render_template('layouts/edit_article.html', article=article)
    except Exception as e:
        print(f"Error: {e}")
        return "Failed to fetch article", 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@routes.route('/update_article', methods=['POST'])
@login_required
def update_article():
    """Mengupdate data artikel di database."""
    article_id = request.form['id']
    title = request.form['title']
    authors = request.form['authors']
    affiliations = request.form['affiliations']
    abstract = request.form['abstract']
    abstractEN = request.form['abstractEN']

    connection = create_connection()
    if connection is None:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor()
        query = """UPDATE articles 
                   SET title = %s, authors = %s, affiliations = %s, abstract = %s, abstractEN = %s 
                   WHERE id = %s"""
        cursor.execute(query, (title, authors, affiliations, abstract, abstractEN,article_id))
        connection.commit()
        return redirect(url_for('routes.articles')) 
    except Exception as e:
        print(f"Error: {e}")
        return "Failed to update article", 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@routes.route("/delete/<int:article_id>", methods=["DELETE"])
@login_required
@role_required('Editor')
def delete_article(article_id):
    try:
        conn = create_connection()
        cursor = conn.cursor()

        # Cek apakah artikel ada di database
        cursor.execute("SELECT filename, file_path FROM articles WHERE id = %s", (article_id,))
        article = cursor.fetchone()

        if not article:
            return jsonify({"error": "Artikel berhasil dihapus"}), 200

        filename, file_path = article

        # Hapus file dari direktori jika ada
        if os.path.exists(file_path):
            os.remove(file_path)

        # Hapus data dari database
        cursor.execute("DELETE FROM articles WHERE id = %s", (article_id,))
        conn.commit()

        return jsonify({"message": "Artikel berhasil dihapus"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close() 


@routes.route('/users', methods=['GET'])
@login_required
@role_required('Chief-Editor')
def users():
    """Menampilkan daftar pengguna dari database."""
    users = get_all_users()
    return render_template('layouts/Users.html', users=users)

@routes.route('/adduser', methods=['GET', 'POST'])
@login_required
@role_required('Chief-Editor')
def add_user():
    """Menambahkan pengguna baru ke dalam database."""
    roles = ['Chief-Editor', 'Manager', 'Editor']
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        connection = create_connection()
        if connection is None:
            flash("Database connection failed", "error")
            return redirect(url_for('routes.users'))

        try:
            cursor = connection.cursor()
            query = "INSERT INTO users (username, role, password) VALUES (%s, %s, %s)"
            cursor.execute(query, (username, role, hashed_password))
            connection.commit()
            flash("User added successfully", "success")
        except Exception as e:
            flash(f"Failed to add user: {e}", "error")
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

        return redirect(url_for('routes.users'))

    return render_template('layouts/adduser.html', roles=roles)  

@routes.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('Chief-Editor')
def edit_user(user_id):
    connection = create_connection()
    if connection is None:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor(dictionary=True)

        if request.method == 'POST':
            username = request.form['username']
            role = request.form['role']
            
            query_update = "UPDATE users SET username = %s, role = %s WHERE id = %s"
            cursor.execute(query_update, (username, role, user_id))
            connection.commit()
            return redirect(url_for('routes.users'))

        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        cursor.execute("SHOW COLUMNS FROM users LIKE 'role'")
        role_data = cursor.fetchone()
        enum_values = role_data['Type'].replace("enum(", "").replace(")", "").replace("'", "").split(",")

        return render_template('layouts/edituser.html', user=user, roles=enum_values)

    except Exception as e:
        print(f"Error: {e}")
        return "Failed to fetch user data", 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@routes.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('Chief-Editor')
def delete_user(user_id):
    """Menghapus pengguna berdasarkan ID."""
    connection = create_connection()
    if connection is None:
        flash("Database connection failed", "error")
        return redirect(url_for('routes.users'))

    try:
        cursor = connection.cursor()
        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        connection.commit()
        flash("User deleted successfully", "success")
    except Exception as e:
        flash(f"Failed to delete user: {e}", "error")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

    return redirect(url_for('routes.users'))


@routes.route('/logout')
def logout():
    session.clear()
    flash("Anda telah logout.", "info")
    return redirect(url_for('routes.login'))
