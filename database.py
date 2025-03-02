# database.py
import mysql.connector
from mysql.connector import Error

def create_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='arsip_teknoif'
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error: {e}")
        return None

def save_metadata(metadata):
    """Save metadata to the database."""
    connection = create_connection()
    if connection is None:
        return "Failed to connect to the database."

    try:
        cursor = connection.cursor()
        query = """
            INSERT INTO articles (id, title, author, affiliation, abstract, file_name, file_path)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        values = (
            metadata['id'], 
            metadata['title'], 
            metadata['author'],
            metadata['affiliation'], 
            metadata['abstract'],
            metadata['file_name'],
            metadata['file_path']
        )
        
        # Validasi input
        if not all(values):
            return "All fields must be filled."

        cursor.execute(query, values)
        connection.commit()
        return "Metadata saved successfully."
    except Error as e:
        print(f"Error: {e}")
        return "Failed to save metadata."
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_all_metadata():
    """Retrieve all metadata from the database."""
    connection = create_connection()
    if connection is None:
        return "Failed to connect to the database."

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM articles")
        return cursor.fetchall()
    except Error as e:
        print(f"Error: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_total_articles():
    """Retrieve the total number of articles from the database."""
    connection = create_connection()
    if connection is None:
        return 0  # Return 0 jika gagal konek

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM articles")  # Ambil total artikel
        total_articles = cursor.fetchone()[0]  # Ambil hasil query
        return total_articles
    except Error as e:
        print(f"Error: {e}")
        return 0
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_total_users():
    """Retrieve the total number of articles from the database."""
    connection = create_connection()
    if connection is None:
        return 0  # Return 0 jika gagal konek

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")  # Ambil total artikel
        total_articles = cursor.fetchone()[0]  # Ambil hasil query
        return total_articles
    except Error as e:
        print(f"Error: {e}")
        return 0
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


def get_all_users():
    """Mengambil semua data pengguna dari database."""
    connection = create_connection()
    if connection is None:
        return []

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        return users
    except Error as e:
        print(f"Error: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_roles():
    """Mengambil semua role yang tersedia dari database."""
    connection = create_connection()
    if connection is None:
        return []

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT name FROM users")  # Pastikan tabel roles ada di database
        roles = cursor.fetchall()
        return roles  # Mengembalikan list role
    except Exception as e:
        print(f"Error fetching roles: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
def get_all_users():
    connection = create_connection()
    if connection is None:
        return []

    try:
        cursor = connection.cursor(dictionary=True)  # Ensure dictionary=True is set
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()  # This will now return a list of dictionaries
        return users
    except Error as e:
        print(f"The error '{e}' occurred")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def update_user_status(user_id, new_status):
    connection = create_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("UPDATE users SET status = %s WHERE id = %s", (new_status, user_id))
        connection.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        connection.close()