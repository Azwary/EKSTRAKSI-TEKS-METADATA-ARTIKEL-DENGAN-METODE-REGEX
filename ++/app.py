import os
import re
import nltk
import PyPDF2
from flask import Flask, request, render_template
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import spacy

# Initialize Flask app
app = Flask(__name__)

# Load NLTK resources
nltk.download('punkt')
nltk.download('stopwords')
nlp = spacy.load("en_core_web_sm")

# Define the path for uploaded files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def extract_text_from_pdf(pdf_path):
     text = ""
     with open(pdf_path, "rb") as file:
          reader = PyPDF2.PdfReader(file)
          if len(reader.pages) > 0:
                 text = reader.pages[0].extract_text()
     text = re.sub(r'^[^L]*\b(License.*)', r'\1', text, flags=re.DOTALL)
     text = re.sub(r'License.{0,20}', '', text, flags=re.DOTALL)
     return text.strip()

def tokenize(text):
     return nltk.word_tokenize(text)

def normalize(text):
     text = text.lower()  # Convert to lowercase
     text = re.sub(r'[^a-z\s]', '', text)  # Remove all non-alphabetic characters and numbers
     text = re.sub(r'\s+', ' ', text).strip()  # Remove excess whitespace
     return text

def remove_stopwords(normalized_text):
    stop_words = set(stopwords.words('indonesian'))
    tokens = word_tokenize(normalized_text)
    return [token for token in tokens if isinstance(token, str) and token not in stop_words]

def extract_metadata(text):
    # Ensure text is a string
    if not isinstance(text, str):
        return {
            "Ftitle": None,
            "authors": [],
            "affiliations": [],
            "abstract": None
        }

    title_match = re.search(r'^(.*?)(?=\s*1\))', text, re.MULTILINE | re.DOTALL)
    if title_match:
        Ftitle = re.sub(r'\s{2,}.*$', '', title_match.group(0), flags=re.MULTILINE | re.DOTALL).strip()
    else:
        Ftitle = None

    # Ekstraksi penulis
    matches = re.findall(r'\s{2,}(.*)', text, flags=re.DOTALL)
    cleaned_text = "\n".join(matches)

    authors = re.findall(r'\b([A-Za-z\s]+?)\d+\)', cleaned_text)
    authors = [author.strip() for author in authors if author.strip().lower() not in ['com', 'id']]  # Menghapus 'com' dan 'id'

#     authors = re.findall(r'\b([A-Za-z\s]+?)\d+\)', text)
#     authors = [author.strip() for author in authors if author.strip().lower() != 'com']  # Menghapus 'com'

    # Ekstraksi afiliasi
    affiliations = re.findall(r'\d+(?:,\d+)*\s*(?:Jurusan|Program Studi\s+)?([A-Z][a-zA-Z\s.]*)(?=\s|e-mail|$)', text)
    affiliations = [affil.strip() for affil in affiliations if affil.strip().lower() != 'jurusan']

    # Ekstraksi abstrak
    abstract_match = re.search(r'(?<=Intisari\s)(.*?)(?=\s*Kata Kunci|$)', text, re.IGNORECASE | re.DOTALL)
    abstract = abstract_match.group(0).strip() if abstract_match else None

    return {
        "Ftitle": Ftitle,
        "authors": authors,
        "affiliations": affiliations,
        "abstract": abstract  # No need to call group() here, as abstract is already a string
    }


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file:
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)
            text = extract_text_from_pdf(file_path)
            normalized_text = normalize(text)
            filtered_tokens = remove_stopwords(normalized_text)
            metadata = extract_metadata(text)
            return render_template('result.html', metadata=metadata, tokens=filtered_tokens)
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)
