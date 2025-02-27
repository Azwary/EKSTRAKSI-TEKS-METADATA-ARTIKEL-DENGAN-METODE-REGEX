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
            "authors": [],
            "affiliations": [],
            "abstract": None
        }

    title_match = re.search(r'^(.*?)(?=\s*1\))', text, re.MULTILINE | re.DOTALL)
    if title_match:
        Ftitle = re.sub(r'\s{2,}.*$', '', title_match.group(0), flags=re.MULTILINE | re.DOTALL).strip()
    else:
        Ftitle = None

    # Extract authors
    matches = re.findall(r'\s{2,}(.*)', text, flags=re.DOTALL)
    cleaned_text = "\n".join(matches)

    authors = re.findall(r'\b([A-Za-z\s]+?)\d+\)', cleaned_text)
    authors = [author.strip() for author in authors if author.strip().lower() not in ['com', 'id']]  # Menghapus 'com' dan 'id'

    # Extract affiliations
    affiliations = re.findall(r'\d+(?:,\d+)*\s*(?:Jurusan\s+)?([A-Z][a-zA-Z\s.]*)(?=\s|e-mail|$)', text)
    affiliations = [affil.strip() for affil in affiliations if affil.strip().lower() != 'jurusan']

    # Ekstraksi abstrak EN
    abstract_matchEN = re.search(r'(?<=Abstract\s)(.*?)(?=\s*Keywords|$)', text, re.IGNORECASE | re.DOTALL)
    abstractEN = abstract_matchEN.group(0).strip() if abstract_matchEN else None

    # Ekstraksi abstrak
    abstract_match = re.search(r'(?<=Intisari\s)(.*?)(?=\s*Kata Kunci|$)', text, re.IGNORECASE | re.DOTALL)
    abstract = abstract_match.group(0).strip() if abstract_match else None


    return {
        "Ftitle": Ftitle,
        "authors": authors,
        "affiliations": affiliations,
        "abstractEN": abstractEN,
        "abstract": abstract
    }