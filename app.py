import os

from flask import Flask
from routes import routes
from datetime import timedelta

# app = Flask(__name__, template_folder='src/templates')
app = Flask(__name__, static_folder='src/static', template_folder='src/templates')
app.secret_key = 'AzwarYusuf'


app.permanent_session_lifetime = timedelta(minutes=10)

app.register_blueprint(routes)


if __name__ == '__main__':
    app.run( debug=True)

