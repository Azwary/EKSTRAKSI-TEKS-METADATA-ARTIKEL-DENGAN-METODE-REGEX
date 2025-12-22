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
    # text = re.sub(r'^[^L]*\b(License.*)', r'\1', text, flags=re.DOTALL) 
    # text = re.sub(r'License.*?(?=([A-Z]{4}))', '', text, flags=re.DOTALL) 
    text = re.sub(r'^.*?([A-Z]{3}.*?)(?=\d{4}).*?(?=[A-Z])', r'\1', text, flags=re.DOTALL)
    text = re.sub(r'DOI.*?(?=[A-Z]{3})', '', text, flags=re.DOTALL) 
    text = re.sub(r'(1\.PENDAHULUAN.+)|(1\. PENDAHULUAN.+)', '', text, flags=re.DOTALL) 
    return text.strip()


def extract_metadata(text):
    if not isinstance(text, str):
        return {
            "Ftitle": None,
            "author": [],
            "affiliation": [],
            "abstract": None
        }
        
    full_text = text

    # Extract title
    title = re.search(
        r'^(.*?)(?=\s+[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\d+\)?)',
        text,
        re.DOTALL | re.MULTILINE
    )
    Ftitle = title.group(1).strip() if title else "not found"

    # Extract author
    author = re.findall(r'([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)(?=\d+\))', text, flags=re.DOTALL)

    # Extract affiliation
    affiliation = re.findall(r'\d+((?:Universitas|Institut|Politeknik|Sekolah Tinggi|University|Institute|Polytechnic|academy)(?:\s+(?!Email\b|E-mail\b|e-mail\b)[A-Z][a-zA-Z\.]*)+)', text)
    affiliation = [affil.strip() for affil in affiliation if affil.strip().lower() ] # '' != 'jurusan'
    
    affiliations = list(dict.fromkeys(affiliation))
    # Ekstraksi abstrak EN
    abstract_matchEN = re.search(r'(?<=Abstract\s)(.*?)(?=\s*Keywords|$)', text, re.IGNORECASE | re.DOTALL)
    abstractEN = abstract_matchEN.group(0).strip() if abstract_matchEN else "Abstract not found"

    # Ekstraksi intisari
    abstract_match = re.search(r'(?<=Intisari\s)(.*?)(?=\s*Kata Kunci|$)', text, re.IGNORECASE | re.DOTALL)
    abstract = abstract_match.group(0).strip() if abstract_match else "Intisari not found"


    return {
        "Ftitle": Ftitle,
        "author": author,
        "affiliation": affiliations,
        "abstractEN": abstractEN,
        "abstract": abstract,
      	"clean": text,
      
    }
    