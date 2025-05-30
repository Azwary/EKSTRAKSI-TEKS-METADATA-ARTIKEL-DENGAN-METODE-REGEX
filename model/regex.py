import re
import PyPDF2

def extract_text_from_pdf(pdf_path):
    text = ""
    with open(pdf_path, "rb") as file:
        reader = PyPDF2.PdfReader(file)
        if len(reader.pages) > 0:
            text = reader.pages[0].extract_text()
    return text.strip()

def clean(text):
    text = re.sub(r'^[^L]*\b(License.*)', r'\1', text, flags=re.DOTALL) 
    text = re.sub(r'License.{0,20}', '', text, flags=re.DOTALL) 
    text = re.sub(r'(1\. PENDAHULUAN.+)', '', text, flags=re.DOTALL) 
    return text.strip()

def tokenize(text):
    tokens = text.split()  # Split text by spaces
    return tokens  # Return list of tokens

def extract_metadata(text):
    if not isinstance(text, str):
        return {
            "Ftitle": None,
            "author": [],
            "affiliation": [],
            "abstract": None
        }

    title_match = re.search(r'(.+?)(?=\s*1\))', text, re.MULTILINE | re.DOTALL)
    if title_match:
        Ftitle = re.sub(r'\s{2,3}[A-Z][a-z]+.*', '', title_match.group(0), flags=re.MULTILINE | re.DOTALL).strip()
    else:
        Ftitle = None

    # Extract author
    matches = re.findall(r'\s{2,3}[A-Z][a-z]+.*', text, flags=re.DOTALL)
    cleaned_text = "\n".join(matches)

    author = re.findall(r'([A-Za-z\s]+?)\d+\)', cleaned_text)
    author = [author.strip() for author in author if author.strip().lower() not in ['com', 'id']]  # Menghapus 'com' dan 'id'

    # Extract affiliation
    affiliation = re.findall(r'\d+((?:Universitas|Institut|Politeknik|Sekolah Tinggi|University|Institute|Polytechnic|academy)(?:\s+(?!Email\b|E-mail\b|e-mail\b|Semarang\b)[A-Z][a-zA-Z\.]*)+)', text)
    affiliation = [affil.strip() for affil in affiliation if affil.strip().lower() ] # '' != 'jurusan'

    # Ekstraksi abstrak EN
    abstract_matchEN = re.search(r'(?<=Abstract\s)(.*?)(?=\s*Keywords|$)', text, re.IGNORECASE | re.DOTALL)
    abstractEN = abstract_matchEN.group(0).strip() if abstract_matchEN else None

    # Ekstraksi abstrak
    abstract_match = re.search(r'(?<=Intisari\s)(.*?)(?=\s*Kata Kunci|$)', text, re.IGNORECASE | re.DOTALL)
    abstract = abstract_match.group(0).strip() if abstract_match else None

    affiliations = list(set(affiliation))

    return {
        "Ftitle": Ftitle,
        "author": author,
        "affiliation": affiliations,
        "abstractEN": abstractEN,
        "abstract": abstract
    }