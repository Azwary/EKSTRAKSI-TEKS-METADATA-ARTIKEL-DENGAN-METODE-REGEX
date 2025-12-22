import os
import subprocess
import platform
import time

from functools import wraps
from flask import Blueprint, render_template, request, redirect, session, url_for, flash, jsonify, send_from_directory, abort
from PyPDF2.errors import PdfReadError
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from model.regex import extract_text_from_pdf, clean, extract_metadata
from database import Error,IntegrityError  , create_connection, save_metadata, get_all_metadata, get_all_users, get_total_articles, get_total_users, get_roles, get_all_users, update_user_status, get_user_by_username
from datetime import datetime

# import pdfplumber
# from PyPDF2 import PdfReader
# from docx import Document
# from docx2pdf import convert
# from fpdf import FPDF

ALLOWED_EXTENSIONS = {'pdf','docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

routes = Blueprint('routes', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start = time.time()
        if 'user_id' not in session:    
            end = time.time()  
            execution_time = end - start
            flash("You Are Not Logged In", "gagal")
            flash(f"Not Logged In: {execution_time:.3f} sec", 'waktu')
            return redirect(url_for('routes.login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    if isinstance(roles, str): 
        roles = (roles,)

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start = time.time()
            if session.get('role') not in roles:
                # flash("Anda tidak memiliki akses ke halaman ini.", "error")
                # return render_template("layouts/error.html", message="Anda tidak memiliki akses ke halaman ini.")
                end = time.time()  
                execution_time = end - start
                flash(f"You do not have access to this page: {execution_time:.3f} sec", 'waktu')
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

        if password != confirm_password:
            end = time.time()
            execution_time = end - start
            flash(f"Password Failed: { execution_time:.3f} sec", 'waktu')
            flash("Password and Password Confirmation Failed", "gagal")
            return redirect(url_for('routes.register'))

        if NoWa.startswith("08"):
            NoWa = "+62" + NoWa[1:]

        hashed_password = generate_password_hash(password)

        connection = create_connection()
        if connection is None:
            flash("Failed to connect to database", "gagal")
            return "Database connection failed", 500

        try:
            cursor = connection.cursor()
            query = """
                INSERT INTO users 
                (nama, username, password, role, email, nama_afiliasi, ID_Scopus, ID_Sinta, ID_GoogleScholar, NoWa, ORCID, status) 
                VALUES (%s, %s, %s, 'Editor', %s, %s, %s, %s, %s, %s, %s, 'Non-Active')
            """
            cursor.execute(query, (
                nama, username, hashed_password, email,
                nama_afiliasi, ID_Scopus, ID_Sinta,
                ID_GoogleScholar, NoWa, ORCID
            ))
            connection.commit()
            end = time.time()
            execution_time = end - start
            flash(f"Registration Successful: {execution_time:.3f} sec", 'waktu')
            flash("Registration Successful! Please Login", "berhasil")
            return redirect(url_for('routes.login'))

        except Exception as e:
            print(f"Error: {e}")
            end = time.time()
            execution_time = end - start
            flash(f"Failed To Register: {execution_time:.3f} sec", 'waktu')
            flash("Failed To Register", "gagal")
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
            if user['status'] != 'Active': 
                flash("Your Account Is Inactive. Contact Admin To Activate The Account.", "gagal")

                end = time.time()
                execution_time = end - start
                flash(f"Account Is Inactive: {execution_time:.3f} sec", 'waktu')

                return redirect(url_for('routes.login'))

            if check_password_hash(user['password'], password):
                session.permanent = True  
                session['user_id'] = user['id']
                session['nama'] = user['nama']
                session['username'] = user['username']
                session['role'] = user['role']
                end = time.time()  
                execution_time = end - start
                flash(f"Role: {execution_time:.3f} sec", 'waktu')
                

                end = time.time()
                execution_time = end - start
                flash(f"Login: {execution_time:.3f} sec", 'waktu')

                last_url = session.get('last_url', 'dashboard') 
                return redirect(last_url)
            else:
                end = time.time()
                execution_time = end - start
                flash(f"Incorrect password: {execution_time:.3f} sec", 'waktu')
                flash("Incorrect password.", "gagal")
        else:
            end = time.time()
            execution_time = end - start
            flash(f"Username Not Found: {execution_time:.3f} sec", 'waktu')
            flash("Username Not Found.", "gagal")

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
    start = time.time()
    total = get_total_articles()
    end = time.time()  
    execution_time = end - start
    flash(f"total Articles:{execution_time:.3f} sec", 'total_a')
    return jsonify({"total": total})

@routes.route('/total-users', methods=['GET'])
@login_required
def total_users():
    start = time.time()
    total = get_total_users()
    end = time.time()  
    execution_time = end - start
    flash(f"total Users:{execution_time:.3f} sec", 'total_b')
    return jsonify({"total": total})

@routes.route('/articles', methods=['GET'])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def articles():
    start = time.time()
    metadata = get_all_metadata()
    end = time.time()  
    execution_time = end - start
    flash(f"Articles: {execution_time:.3f} sec", 'waktu')

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


def convert_file_to_pdf(file_path, output_dir):
    system = platform.system()
    
    # Tentukan path LibreOffice berdasarkan OS
    if system == "Windows":
        libreoffice_path = r'"C:\Program Files\LibreOffice\program\soffice.exe"'
    else:
        libreoffice_path = '/opt/libreoffice7.3/program/soffice'

    # Jalankan konversi
    subprocess.run(
        f'{libreoffice_path} --headless --convert-to pdf --outdir "{output_dir}" "{file_path}"',
        shell=True
    )
    
    # Bangun path file PDF hasil konversi
    filename_wo_ext = os.path.splitext(os.path.basename(file_path))[0]
    pdf_file_path = os.path.join(output_dir, filename_wo_ext + '.pdf')

    # Cek apakah file PDF berhasil dibuat
    if os.path.exists(pdf_file_path):
        return pdf_file_path
    else:
        return None


@routes.route('/upload', methods=['GET', 'POST'])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("Extraction failed, no file found", "gagal")
            return render_template('layouts/upload.html')

        file = request.files['file']
        if file.filename == '':
            flash("Tidak ada file yang dipilih.", "gagal")
            return render_template('layouts/upload.html')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            original_ext = filename.rsplit('.', 1)[1].lower()
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)

            if original_ext == 'docx':
                try:
                    output_dir = os.path.dirname(file_path)
                    pdf_path = convert_file_to_pdf(file_path, output_dir)

                    if not os.path.exists(pdf_path):
                        flash("File hasil konversi tidak ditemukan.", "gagal")
                        return render_template('layouts/upload.html')

                    file_path = pdf_path
                    filename = os.path.basename(pdf_path)

                except Exception as e:
                    flash(f"Gagal konversi .docx: {e}", "gagal")
                    return render_template('layouts/upload.html')
                
            if file_path.endswith('.pdf'):
                try:
                    start = time.time()
                    text = extract_text_from_pdf(file_path)

                    if not text.strip():
                        flash("Teks kosong setelah strip.", "gagal")
                        return render_template('layouts/upload.html')

                    cleaned_text = clean(text)
                    metadata = extract_metadata(cleaned_text)
                    title = metadata.get("title", "").strip()

                    if title:
                        connection = create_connection()
                        cursor = connection.cursor(dictionary=True)
                        query = "SELECT id FROM articles WHERE title = %s"
                        cursor.execute(query, (title,))
                        result = cursor.fetchone()
                        cursor.close()
                        connection.close()

                        if result:
                            flash(f"Judul '{title}' sudah diekstrak sebelumnya.", "gagal")
                            return render_template('layouts/upload.html')

                    end = time.time()
                    execution_time = end - start
                    flash(f"Extraction Successful: {execution_time:.3f} sec", "waktu")
                    flash("Extraction Successful", "berhasil")
                    metadata["full"] = text

                    return render_template('layouts/result.html', metadata=metadata, filename=filename, file_path=file_path)

                except Exception as e:
                    flash(f"Terjadi kesalahan saat ekstraksi: {str(e)}", "gagal")
                    return render_template('layouts/upload.html')

        flash("Extraction failed, format is not PDF/DOCX", "gagal")
        return render_template('layouts/upload.html')

    return render_template('layouts/upload.html')


@routes.route("/download/<filename>")
def download_file(filename):
    filename = secure_filename(filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File tidak ditemukan"}), 404

    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@routes.route('/results', methods=['POST'])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def results():
    start = time.time()
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
                abstract = request.form.get("abstract", "").strip()
                if not abstract or abstract.lower() == "Abstract not found":
                    flash("Data abstract tidak ada", "gagal")
                    # return redirect(url_for('routes.articles'))
            
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
                end = time.time()
                execution_time = end - start
                # flash(f"Metadata saved successfully: {execution_time:.3f} sec", 'waktu')
                flash('Metadata saved successfully', 'berhasil')
            except IntegrityError:
                title = request.form.get("title", "").strip()
                flash(f"Title '{title}' already available", "gagal")
            except Exception  as e:
                end = time.time()
                execution_time = end - start
                # flash(f"Metadata saved failed: {execution_time:.3f} sec", 'waktu')
                flash('Metadata saved failed ', 'gagal')
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
    
    return "Tidak ada data untuk diedit", 400

@routes.route('/save', methods=['POST'])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def save_metadata():
    try:
        start = time.time()
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
            end = time.time()
            execution_time = end - start
            flash(f"Metadata saved successfully: {execution_time:.3f} sec", 'waktu')
            flash('Metadata saved successfully', 'berhasil')
        else:
            flash('Connection to database failed! ', 'gagal')

    except IntegrityError:
        title = request.form.get("title", "").strip()
        flash(f"Title '{title}' already available", "gagal")

    except Exception  as e:
        end = time.time()
        execution_time = end - start
        flash(f"Metadata saved failed: {execution_time:.3f} sec", 'waktu')
        flash(f'Metadata saved failed{e}', 'gagal')
        # flash(f'Connection to database failed!', 'gagal')

    return redirect(url_for('routes.articles'))


@routes.route('/edit/<int:article_id>', methods=['GET'])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def edit_article(article_id):
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
        start = time.time()
        cursor = connection.cursor()
        query = """UPDATE articles 
                   SET title = %s, author = %s, affiliation = %s, abstract = %s, abstractEN = %s 
                   WHERE id = %s"""
        cursor.execute(query, (title, author, affiliation, abstract, abstractEN,article_id))
        connection.commit()
        end = time.time()  
        execution_time = end - start
        flash(f"Update Article Successfully: {execution_time:.3f} sec", 'waktu')
        flash("Update Article Successfully", "berhasil")
        return redirect(url_for('routes.articles')) 
    except Exception as e:
        print(f"Error: {e}")
        end = time.time()  
        execution_time = end - start
        flash(f"Update Article failed: {execution_time:.3f} sec", 'waktu')
        flash("Update Article failed", "gagal")
        return redirect(url_for('routes.articles')) 
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@routes.route("/delete/<int:article_id>", methods=["POST"])
@login_required
@role_required(('Editor', 'Manager', 'Chief-Editor'))
def delete_article(article_id):
    connection = create_connection()
    if connection is None:
        flash("Database connection failed", "gagal")
        return redirect(url_for('routes.articles'))

    try:
        start = time.time()
        cursor = connection.cursor()
        query = "DELETE FROM articles WHERE id = %s"
        cursor.execute(query, (article_id,))
        connection.commit()
        end = time.time() 
        execution_time = end - start
        flash(f"Article Delete: {execution_time:.3f} sec", 'waktu')
        flash("Article Delete Successfully", "berhasil")
    except Exception as e:
        flash(f"Failed to delete article: {e}", "gagal")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

    return redirect(url_for('routes.articles'))

@routes.route('/grafik', methods=['GET'])
@login_required
@role_required(('Manager', 'Chief-Editor'))
def grafik_view():
    import time
    from collections import Counter
    start = time.time()

    tipe = request.args.get('tipe', 'affiliation')
    conn = create_connection()
    cursor = conn.cursor()

    if tipe == 'affiliation':
        query = "SELECT affiliation FROM articles"
        cursor.execute(query)
        rows = cursor.fetchall()

        affiliation_counter = Counter()
        for row in rows:
            if len(row) == 0 or not row[0]:
                continue

            affiliations = row[0].split(',')
            for aff in affiliations:
                cleaned = aff.strip()
                if cleaned:
                    affiliation_counter[cleaned] += 1

        result = sorted(affiliation_counter.items(), key=lambda x: x[0].lower())
        # result = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        data = [{"label": name, "value": count} for name, count in result]

    elif tipe == 'author':
        query = "SELECT author FROM articles"
        cursor.execute(query)
        rows = cursor.fetchall()

        author_counter = Counter()
        for row in rows:
            if len(row) == 0 or not row[0]:
                continue

            authors = row[0].split(',')
            for author in authors:
                cleaned = author.strip()
                if cleaned:
                    author_counter[cleaned] += 1

        # Urut berdasarkan abjad (A-Z)
        result = sorted(author_counter.items(), key=lambda x: x[0].lower())
        # result = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        data = [{"label": name, "value": count} for name, count in result]
    else:
        flash("Invalid tipe grafik", "error")
        return redirect(url_for('routes.dashboard'))  
    cursor.close()
    conn.close()

    end = time.time()
    execution_time = end - start
    flash(f"Graph Load: {execution_time:.3f} sec", 'waktu')

    return render_template('layouts/grafik.html', data=data, tipe=tipe)

@routes.route('/grafik/judul')
@login_required
@role_required(('Manager', 'Chief-Editor'))
def get_titles_by_label():
    tipe = request.args.get('tipe')
    label = request.args.get('label')

    if not tipe or not label:
        return jsonify([])

    conn = create_connection()
    cursor = conn.cursor()

    if tipe == 'author':
        query = "SELECT title FROM articles WHERE author LIKE %s"
        cursor.execute(query, [f"%{label}%"])
    elif tipe == 'affiliation':
        query = "SELECT title FROM articles WHERE affiliation LIKE %s"
        cursor.execute(query, [f"%{label}%"])
    else:
        return jsonify([])

    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    titles = [row[0] for row in rows if row[0]]
    return jsonify(titles)


@routes.route('/users', methods=['GET'])
@login_required
@role_required(('Manager'))
def users():
    start = time.time()
    users = get_all_users()
    end = time.time()  
    execution_time = end - start
    flash(f"Users: {execution_time:.3f} sec", 'waktu')
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

        if password != confirm_password:
            end = time.time()  
            execution_time = end - start
            flash(f"Password and password confirmation failed: {execution_time:.3f} sec", 'waktu')
            flash("Password and password confirmation failed", "gagal")
            return redirect(url_for('routes.add_user'))

        hashed_password = generate_password_hash(password)

        connection = create_connection()
        if connection is None:
            flash("Database connection failed", "gagal")
            return redirect(url_for('routes.users'))

        try:
            cursor = connection.cursor()
            start = time.time()
            query = """
                INSERT INTO users (
                    nama, username, password, role, email, nama_afiliasi, 
                    ID_Scopus, ID_Sinta, ID_GoogleScholar, NoWa, ORCID, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Active')
            """
            values = (
                nama, username, hashed_password, role, email, nama_afiliasi,
                ID_Scopus, ID_Sinta, ID_GoogleScholar, NoWa, ORCID
            )
            cursor.execute(query, values)
            connection.commit()
            end = time.time() 
            execution_time = end - start
            flash(f"Add User Successfully: {execution_time:.3f} sec", 'waktu')
            flash("User Add Successfully", "berhasil")
        except Exception as e:
            end = time.time() 
            execution_time = end - start
            flash(f"Add User Failed: {execution_time:.3f} sec", 'waktu')
            flash(f"Failed to add user", "gagal")
            # flash(f"Failed to add user: {e}", "gagal")
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
            if password:
                if password != confirm_password:
                    flash("Password and confirmation do not match!", "gagal")
                    return redirect(url_for('routes.edit_user', user_id=user_id))
                hashed_password = generate_password_hash(password)
                update_fields += ", password = %s"
                values.append(hashed_password)
            values.append(user_id)
            start=time.time()
            query_update = f"UPDATE users SET {update_fields} WHERE id = %s"
            cursor.execute(query_update, values)
            connection.commit()
            end = time.time() 
            execution_time = end - start
            flash(f"Update User Successfully: {execution_time:.3f} sec", 'waktu')
            flash("Update User Successfully", "berhasil")
            return redirect(url_for('routes.users'))

        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found", "gagal")
            return redirect(url_for('routes.users'))

        cursor.execute("SHOW COLUMNS FROM users LIKE 'role'")
        role_data = cursor.fetchone()
        enum_values = role_data['Type'].replace("enum(", "").replace(")", "").replace("'", "").split(",")

        return render_template('layouts/edituser.html', user=user, roles=enum_values)

    except Exception as e:
        # print(f"Error: {e}")
        end = time.time() 
        execution_time = end - start
        flash(f"Update User failed: {execution_time:.3f} sec", 'waktu')
        flash("Update User failed", "gagal")
        # flash("An error occurred while updating the user", "gagal")
        return redirect(url_for('routes.users'))
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@routes.route('/update-status/<int:user_id>/<status>', methods=['POST'])
@login_required
@role_required(('Manager'))
def update_status(user_id, status):
    start = time.time()
    if status not in ["Active", "Non-Active"]:
        return "Invalid status", 400  
    success = update_user_status(user_id, status)
    if success:
        end = time.time()  
        execution_time = end - start
        flash(f"Update succeed: {execution_time:.3f} sec", 'waktu')
        flash("Update succeed", "berhasil")
        return redirect(url_for('routes.users'))
    else:
        end = time.time()  
        execution_time = end - start
        flash(f"Update failed: {execution_time:.3f} sec", 'waktu')
        flash("Update failed", "gagal")
        # return "Gagal memperbarui status", 500


@routes.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(('Manager'))
def delete_user(user_id):
    connection = create_connection()
    if connection is None:
        flash("Database connection failed", "gagal")
        return redirect(url_for('routes.users'))
    try:
        start = time.time() 
        cursor = connection.cursor()
        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        connection.commit()
        end = time.time() 
        execution_time = end - start
        flash(f"User Delete: {execution_time:.3f} sec", 'waktu')
        flash("User Delete Successfully", "berhasil")
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
    flash("Logout Successful", "berhasil")
    flash(f"Logout Successful: {execution_time:.3f} sec", 'waktu')
    return redirect(url_for('routes.login'))

