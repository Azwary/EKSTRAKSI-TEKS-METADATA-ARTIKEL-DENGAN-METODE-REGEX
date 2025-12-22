import mysql.connector
from mysql.connector import Error, IntegrityError

def create_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',           
            user='root',
            password='root',
            database='arsip_teknoif'
        )
        if connection.is_connected():
            return connection
    except Exception as e:
        print(f"Error: {e}")
        return None

def save_metadata(metadata):
    connection = create_connection()
    if connection is None:
        return "Failed to connect to the database."

    try:
        cursor = connection.cursor()
        query = """
            INSERT INTO articles (id, title, author, affiliation, abstract, abstract, file_name, file_path)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        values = (
            metadata['id'], 
            metadata['title'], 
            metadata['author'],
            metadata['affiliation'], 
            metadata['abstract'],
            metadata['abstractEN'],
            metadata['file_name'],
            metadata['file_path']
        )
        
        if not all(values):
            return "All fields must be filled."

        cursor.execute(query, values)
        connection.commit()
        return "Metadata saved successfully."
    except Exception as e:
        print(f"Error: {e}")
        return "Failed to save metadata."
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_all_metadata():
    connection = create_connection()
    if connection is None:
        return "Failed to connect to the database."

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM articles")
        return cursor.fetchall()
    except Exception as e:
        print(f"Error: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_total_articles():
    connection = create_connection()
    if connection is None:
        return 0 

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM articles")  
        total_articles = cursor.fetchone()[0]  
        return total_articles
    except Exception as e:
        print(f"Error: {e}")
        return 0
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_total_users():
    connection = create_connection()
    if connection is None:
        return 0  

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")  
        total_articles = cursor.fetchone()[0] 
        return total_articles
    except Exception as e:
        print(f"Error: {e}")
        return 0
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_user_by_username(username):
    connection = create_connection()
    if connection is None:
        return None

    try:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query,(username,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()  

def get_all_users():
    connection = create_connection()
    if connection is None:
        return []

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        return users
    except Exception as e:
        print(f"Error: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_roles():
    connection = create_connection()
    if connection is None:
        return []

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT name FROM users")  
        roles = cursor.fetchall()
        return roles 
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
        cursor = connection.cursor(dictionary=True)  
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()  
        return users
    except Exception as e:
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
