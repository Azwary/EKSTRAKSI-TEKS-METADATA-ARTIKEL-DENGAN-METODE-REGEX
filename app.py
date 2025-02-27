import os

from flask import Flask
from Routes import routes

# app = Flask(__name__, template_folder='src/templates')
app = Flask(__name__, static_folder='src/static', template_folder='src/templates')

app.secret_key = os.urandom(24)
app.register_blueprint(routes)


if __name__ == '__main__':
    app.run(debug=True)
