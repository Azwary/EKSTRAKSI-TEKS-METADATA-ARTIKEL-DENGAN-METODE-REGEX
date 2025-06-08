import os

from flask import Flask
from routes import routes
from datetime import timedelta

# app = Flask(__name__, template_folder='src/templates')
app = Flask(__name__, static_folder='src/static', template_folder='src/templates')
app.secret_key = 'rahasia_tetap_untuk_development_123456'

# Atur session lifetime 5 menit
app.permanent_session_lifetime = timedelta(minutes=2)

app.register_blueprint(routes)


if __name__ == '__main__':
    app.run(debug=True)
