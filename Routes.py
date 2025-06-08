import os
from functools import wraps
from flask import Blueprint, render_template, request, redirect, session, url_for, flash, jsonify, send_from_directory, abort
from PyPDF2.errors import PdfReadError
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from model.regex import extract_text_from_pdf, clean, extract_metadata
from database import Error, create_connection, save_metadata, get_all_metadata, get_all_users, get_total_articles, get_total_users, get_roles, get_all_users, update_user_status, get_user_by_username
from datetime import datetime
import time

ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
            flash("You are not logged in", "gagal")
            return redirect(url_for('routes.login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """Dekorator untuk membatasi akses berdasarkan peran pengguna."""
    if isinstance(roles, str): 
        roles = (roles,)

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in roles:
                # flash("Anda tidak memiliki akses ke halaman ini.", "error")
                # return render_template("layouts/error.html", message="Anda tidak memiliki akses ke halaman ini.")
                flash("You do not have access to this page.", "gagal")
                return redirect(request.referrer or '/')
                # return render_template("layouts/error.html", message="Anda tidak memiliki akses ke halaman ini.")
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
    start = time.time()
    if request.method == 'POST':
        # Ambil data dari form
        nama = request.form['nama']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        nama_afiliasi = request.form['nama_afiliasi']
        ID_Scopus = request.form['ID_Scopus']
        ID_Sinta = request.form['ID_Sinta']
        ID_GoogleScholar = request.form['ID_GoogleScholar']
        NoWa = request.form['NoWa'].strip().replace(" ", "").replace("-", "")
        ORCID = request.form['ORCID']

        # Validasi konfirmasi password
        if password != confirm_password:
            end = time.time()
            flash(f"{end - start:.3f} sec", 'waktu')
            flash("Password and password confirmation failed", "gagal")
            return redirect(url_for('routes.register'))

        # Format NoWa: ubah 08xxx -> +628xxx
        if NoWa.startswith("08"):
            NoWa = "+62" + NoWa[1:]

        # Hash password
        hashed_password = generate_password_hash(password)

        # Koneksi ke database
        connection = create_connection()
        if connection is None:
            flash("Failed to connect to database", "gagal")
            return "Database connection failed", 500

        try:
            cursor = connection.cursor()
            query = """
                INSERT INTO users 
                (nama, username, password, role, email, nama_afiliasi, ID_Scopus, ID_Sinta, ID_GoogleScholar, NoWa, ORCID, status) 
                VALUES (%s, %s, %s, 'Editor', %s, %s, %s, %s, %s, %s, %s, 'nonaktif')
            """
            cursor.execute(query, (
                nama, username, hashed_password, email,
                nama_afiliasi, ID_Scopus, ID_Sinta,
                ID_GoogleScholar, NoWa, ORCID
            ))
            connection.commit()
            end = time.time()
            flash(f"{end - start:.3f} sec", 'waktu')
            flash("Registration successful! Please login.", "berhasil")
            return redirect(url_for('routes.login'))

        except Exception as e:
            print(f"Error: {e}")
            end = time.time()
            flash(f"{end - start:.3f} sec", 'waktu')
            flash("Failed to register", "gagal")
            return redirect(url_for('routes.register'))

        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    return render_template('auth/register.html')

@routes.route('/login', methods=['GET', 'POST'])
def login():
    start = time.time()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = get_user_by_username(username)

        if user:
            if user['status'] != 'aktif': 
                flash("Your account is inactive. Contact admin to activate the account.", "gagal")

                end = time.time()
                execution_time = end - start
                flash(f"{execution_time:.3f} sec", 'waktu')

                return redirect(url_for('routes.login'))

            if check_password_hash(user['password'], password):
                session.permanent = True  
                session['user_id'] = user['id']
                session['nama'] = user['nama']
                session['username'] = user['username']
                session['role'] = user['role']

                end = time.time()
                execution_time = end - start
                flash(f"{execution_time:.3f} sec", 'waktu')

                last_url = session.get('last_url', 'dashboard') 
                return redirect(last_url)
            else:
                # Username benar, password salah
                flash("Incorrect password.", "gagal")
        else:
            # Username tidak ditemukan
            flash("Username not found.", "gagal")

        # Akhir dari POST gagal (user not found atau password salah)
        end = time.time()
        execution_time = end - start
        flash(f"{execution_time:.3f} sec", 'waktu')

    return render_template('auth/login.html')


@routes.before_app_request
def refresh_session():
    session.modified = True  

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
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def articles():
    metadata = get_all_metadata()
    page = request.args.get('page', 1, type=int)
    per_page = 8
    start = (page - 1) * per_page
    end = start + per_page

    paginated_data = metadata[start:end]
    total_pages = (len(metadata) + per_page - 1) // per_page

    return render_template('layouts/articles.html', 
                           articles=paginated_data,
                           current_page=page,
                           total_pages=total_pages,
                           all_articles=metadata)


# @routes.route('/articles', methods=['GET'])
# @login_required
# @role_required(('Editor', 'Manager', 'Chief-Editor'))
# def articles():
#     metadata = get_all_metadata()
#     return render_template('layouts/articles.html', articles=metadata)

@routes.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    error_message = None
    success_message = None
    
    if request.method == 'POST':
        if 'file' not in request.files:
            error_message = 'Tidak ada file yang dipilih.'
        else:
            file = request.files['file']
            if file.filename == '':
                error_message = 'Tidak ada file yang dipilih.'
            elif file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                try:
                    start = time.time()
                    text = extract_text_from_pdf(file_path)
                    cleaned_text = clean(text)
                    metadata = extract_metadata(cleaned_text)
                    end = time.time()
                    execution_time = end - start
                    flash(f"{execution_time:.3f} sec", 'waktu')
                    return render_template('layouts/result.html', metadata=metadata, filename=filename, file_path=file_path)
                except PdfReadError:
                    error_message = 'Format tidak didukung atau file PDF rusak.'
            else:
                error_message = 'Format tidak didukung. Harap unggah file PDF.'
    

    return render_template('layouts/upload.html', error_message=error_message, success_message=success_message)


@routes.route("/download/<filename>")
def download_file(filename):
    filename = secure_filename(filename)  # Amankan nama file
    file_path = os.path.join(PDF_FOLDER, filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File tidak ditemukan"}), 404  # Mengembalikan status 404

    return send_from_directory(PDF_FOLDER, filename, as_attachment=True)

@routes.route('/results', methods=['POST'])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def results():
    action = request.form.get('action')

    if action == 'edit':
        metadata = {
            "title": request.form.get("title"),
            "author": request.form.get("author"),
            "affiliation": request.form.get("affiliation"),
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
                sql = """INSERT INTO articles (title, author, affiliation, abstract, abstractEN, filename, file_path)
                         VALUES (%s, %s, %s, %s, %s, %s, %s)"""
                values = (
                    request.form.get("title"),
                    request.form.get("author"),
                    request.form.get("affiliation"),
                    request.form.get("abstract"),
                    request.form.get("abstractEN"),
                    request.form.get("filename"),
                    request.form.get("file_path"),
                )
                cursor.execute(sql, values)
                connection.commit()
                cursor.close()
                connection.close()
                flash('Metadata saved successfully!', 'berhasil')
            except Error as e:
                flash(f'Failed to save metadata: {e}', 'gagal')
                print(f"Error: {e}")
        else:
            flash('Connection to database failed!', 'gagal')

    return redirect(url_for('routes.articles'))


@routes.route('/edit', methods=['GET', 'POST'])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def edit_metadata():
    if request.method == 'POST':
        metadata = {
            "title": request.form.get("title"),
            "author": request.form.get("author"),
            "affiliation": request.form.get("affiliation"),
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
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def save_metadata():
    try:
        connection = create_connection()
        if connection:
            cursor = connection.cursor()
            sql = """INSERT INTO articles (title, author, affiliation, abstract, abstractEN, filename, file_path)
                     VALUES (%s, %s, %s, %s, %s, %s, %s)"""
            values = (
                request.form.get("title"),
                request.form.get("author"),
                request.form.get("affiliation"),
                request.form.get("abstract"),
                request.form.get("abstractEN"),
                request.form.get("filename"),
                request.form.get("file_path"),
            )
            cursor.execute(sql, values)
            connection.commit()
            cursor.close()
            connection.close()
            flash('Metadata saved successfully!', 'berhasil')
        else:
            flash('Connection to database failed!', 'gagal')
    except Error as e:
        flash(f'Failed to save metadata: {e}', 'gagal')
        print(f"Error: {e}")

    return redirect(url_for('routes.articles'))


@routes.route('/edit/<int:article_id>', methods=['GET'])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
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
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def update_article():
    """Mengupdate data artikel di database."""
    article_id = request.form['id']
    title = request.form['title']
    author = request.form['author']
    affiliation = request.form['affiliation']
    abstract = request.form['abstract']
    abstractEN = request.form['abstractEN']

    connection = create_connection()
    if connection is None:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor()
        query = """UPDATE articles 
                   SET title = %s, author = %s, affiliation = %s, abstract = %s, abstractEN = %s 
                   WHERE id = %s"""
        cursor.execute(query, (title, author, affiliation, abstract, abstractEN,article_id))
        connection.commit()
        return redirect(url_for('routes.articles')) 
    except Exception as e:
        print(f"Error: {e}")
        return "Failed to update article", 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@routes.route("/delete/<int:article_id>", methods=["POST"])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def delete_article(article_id):
    try:
        conn = create_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT filename, file_path FROM articles WHERE id = %s", (article_id,))
        article = cursor.fetchone()

        if not article:
            return jsonify({"error": "Artikel tidak ditemukan"}), 404

        filename, file_path = article

        if os.path.exists(file_path):
            os.remove(file_path)

        cursor.execute("DELETE FROM articles WHERE id = %s", (article_id,))
        conn.commit()

        return jsonify({"message": "Article successfully deleted"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()


@routes.route('/users', methods=['GET'])
@login_required
@role_required(('Manager'))
def users():
    users = get_all_users()
    return render_template('layouts/Users.html', users=users)

@routes.route('/adduser', methods=['GET', 'POST'])
@login_required
@role_required(('Manager'))
def add_user():
    roles = ['Editor', 'Manager', 'Chief-Editor']
    if request.method == 'POST':
        nama = request.form['nama']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        email = request.form['email']
        nama_afiliasi = request.form.get('nama_afiliasi')
        ID_Scopus = request.form.get('ID_Scopus')
        ID_Sinta = request.form.get('ID_Sinta')
        ID_GoogleScholar = request.form.get('ID_GoogleScholar')
        NoWa = request.form.get('NoWa')
        ORCID = request.form.get('ORCID')

        # Validasi password dan konfirmasi
        if password != confirm_password:
            flash("Password and password confirmation failed", "gagal")
            return redirect(url_for('routes.add_user'))

        hashed_password = generate_password_hash(password)

        connection = create_connection()
        if connection is None:
            flash("Database connection failed", "gagal")
            return redirect(url_for('routes.users'))

        try:
            cursor = connection.cursor()
            query = """
                INSERT INTO users (
                    nama, username, password, role, email, nama_afiliasi, 
                    ID_Scopus, ID_Sinta, ID_GoogleScholar, NoWa, ORCID
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (
                nama, username, hashed_password, role, email, nama_afiliasi,
                ID_Scopus, ID_Sinta, ID_GoogleScholar, NoWa, ORCID
            )
            cursor.execute(query, values)
            connection.commit()
            flash("User added successfully", "berhasil")
        except Exception as e:
            flash(f"Failed to add user: {e}", "gagal")
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

        return redirect(url_for('routes.users'))

    return render_template('layouts/adduser.html', roles=roles)



@routes.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(('Manager'))
def edit_user(user_id):
    connection = create_connection()
    if connection is None:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor(dictionary=True)

        if request.method == 'POST':
            nama = request.form['nama']
            username = request.form['username']
            role = request.form['role']
            email = request.form['email']
            nama_afiliasi = request.form.get('nama_afiliasi')
            ID_Scopus = request.form.get('ID_Scopus')
            ID_Sinta = request.form.get('ID_Sinta')
            ID_GoogleScholar = request.form.get('ID_GoogleScholar')
            NoWa = request.form.get('NoWa')
            ORCID = request.form.get('ORCID')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            update_fields = """
                nama = %s,
                username = %s,
                role = %s,
                email = %s,
                nama_afiliasi = %s,
                ID_Scopus = %s,
                ID_Sinta = %s,
                ID_GoogleScholar = %s,
                NoWa = %s,
                ORCID = %s
            """
            values = [
                nama, username, role, email, nama_afiliasi,
                ID_Scopus, ID_Sinta, ID_GoogleScholar, NoWa, ORCID
            ]

            # Jika password diisi dan cocok, tambahkan ke update
            if password:
                if password != confirm_password:
                    flash("Password and confirmation do not match!", "gagal")
                    return redirect(url_for('routes.edit_user', user_id=user_id))
                hashed_password = generate_password_hash(password)
                update_fields += ", password = %s"
                values.append(hashed_password)

            values.append(user_id)
            query_update = f"UPDATE users SET {update_fields} WHERE id = %s"
            cursor.execute(query_update, values)
            connection.commit()
            flash("Updated successfully", "berhasil")
            return redirect(url_for('routes.users'))

        # GET Method – Ambil data user & role
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found", "gagal")
            return redirect(url_for('routes.users'))

        # Ambil enum values dari kolom 'role'
        cursor.execute("SHOW COLUMNS FROM users LIKE 'role'")
        role_data = cursor.fetchone()
        enum_values = role_data['Type'].replace("enum(", "").replace(")", "").replace("'", "").split(",")

        return render_template('layouts/edituser.html', user=user, roles=enum_values)

    except Exception as e:
        print(f"Error: {e}")
        flash("An error occurred while updating the user", "gagal")
        return redirect(url_for('routes.users'))
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@routes.route('/update-status/<int:user_id>/<status>', methods=['POST'])
@login_required
@role_required(('Manager'))
def update_status(user_id, status):
    if status not in ["aktif", "nonaktif"]:
        return "Invalid status", 400  
    success = update_user_status(user_id, status)
    if success:
        flash("succeed", "berhasil")
        return redirect(url_for('routes.users'))
    else:
        flash("Fail", "gagal")
        return "Gagal memperbarui status", 500


@routes.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(('Manager'))
def delete_user(user_id):
    """Menghapus pengguna berdasarkan ID."""
    connection = create_connection()
    if connection is None:
        flash("Database connection failed", "gagal")
        return redirect(url_for('routes.users'))

    try:
        cursor = connection.cursor()
        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        connection.commit()
        flash("User deleted successfully", "berhasil")
    except Exception as e:
        flash(f"Failed to delete user: {e}", "gagal")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

    return redirect(url_for('routes.users'))


@routes.route('/logout')
def logout():
    start = time.time()
    session.clear()
    end = time.time()  
    execution_time = end - start
    flash("logout successful", "berhasil")
    flash(f"{execution_time:.3f} sec", 'waktu')
    return redirect(url_for('routes.login'))

