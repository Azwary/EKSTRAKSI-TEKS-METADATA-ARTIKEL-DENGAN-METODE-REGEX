# EKSTAKSI TEKS METADATA ARTIKEL DENGAN METODE REGEX
[![Python ](https://img.shields.io/badge/Python-blue.svg)](https://www.python.org/downloads/)
<!--
[![GitHub license](https://img.shields.io/github/license/onpilot/sentimen-bahasa.svg)](https://github.com/onpilot/sentimen-bahasa/blob/master/LICENSE)
-->



pengelompokan metadata artikel berdasarkan kebutuhan di `Teknoif`.
> ###### _Metadata bisa dihasilkan secara otomatis dari dokumen, sehingga mempercepat proses pengelolaan dan pencarian informasi yang relevan di `Teknoif`. Penggunaan ReGex untuk mengenali pola yang dapat digunakan untuk mendeskripsikan pola dari kata yang ingin dicari **\*Note:** kebuthan teknoif `Title, Author, Affiliation, dan abstract `._

## library
- **[flask:](https://flask.palletsprojects.com/en/stable/installation/#python-version)** framework aplikasi web yang ringan dan fleksibel;
- **[werkzeug:](https://werkzeug.palletsprojects.com/en/stable/installation/)** pustaka WSGI (Web Server Gateway Interface) yang menyediakan alat dan utilitas untuk membangun aplikasi web di Python;
- **[PyPDF2:](https://pypdf2.readthedocs.io/en/3.x/user/installation.html)** operasi pada file PDF, seperti membaca, menggabungkan, memisahkan, dan memodifikasi konten PDF;
- **[mysql-connector-python:](https://dev.mysql.com/doc/connector-python/en/connector-python-installation.html)** menghubungkan aplikasi Python dengan database MySQL;
 <!--**mysql-connector-python:** `term presence`, `bag of words`, `TF-IDF`;-->
 <!--**Sintesis Data:** `SVM-SMOTE`;-->
 <!--**Classifier:** `SVM` dengan *linear kernel*.-->
 <!--
## tl;dr
Repositori ini dibuat untuk mengevaluasi performa leksikon dan metode ekstraksi fitur pada analisis sentimen teks berbahasa Indonesia mengenai penanganan Covid-19 dengan *Support Vector Machine (SVM)*. Pendekatan analisis sentimen dilakukan dengan pemelajaran semisupervisi—menggabungkan *pendekatan berbasis leksikon* dan *pendekatan berbasis pemelajaran mesin*. Setiap *jupyter notebook (ipynb)* disertai dengan petunjuk. Algoritma dibuat dengan memanfaatkan modul `RegEx` bawaan Python dan library [`NLTK`](https://www.nltk.org/), [`Scikit-learn`](https://scikit-learn.org/), juga [`imbalanced-learn`](https://imbalanced-learn.org/). Validasi dilakukan dengan `k-Fold cv` setelah sebelumnya data disintesis (*oversampling*) dengan *borderline SMOTE SVM* atau `SVM-SMOTE`.

## Algoritma yang termasuk
- [x] Pembersihan kata/prapengolahan teks
- [x] Penggantian kata tidak baku
- [x] Penghapusan *stop words*
- [x] Pelabelan leksikon: *InSet*, *sentiwords_id* (dari *sentistrength_id*) 
- [x] Ekstraksi fitur: *term presence*, *BoW*, *TF-IDF*
- [x] Sintesis data: *SVM-SMOTE*
- [x] Klasifikasi: *SVM*
- [x] *Plotting*

## Prasyarat
* pandas >= 0.25.0
* numpy >= 1.16.6
* nltk
* scikit-learn
* imbalanced-learn
* jupyterlab

## Instalasi
**Prasyarat**

instal *package* satu per satu

`pip3 install --user --upgrade [nama package]` atau

**Clone Repositori**

```bash
git clone https://github.com/onpilot/sentimen-bahasa.git
cd sentimen-bahasa
pip3 install -r requirements.txt
jupyter-lab
```

## FAQ
> Saya punya instalasi Python versi lama untuk projek lain. Apa perlu di-*uninstall* dulu?

Ya. Atau gunakan aplikasi yang bisa memanajemen instalasi Python, seperti [Conda](https://conda.io/) atau [Scoop](https://github.com/ScoopInstaller/Scoop).

> Error: Microsoft Visual C++ 14.0 or greater is required!
 
Pengguna Windows perlu compiler [Visual C++ 14.0 Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) atau versi di atasnya untuk package scikit-learn.


## Publikasi
Publikasi mengenai projek ini bisa dilihat di: http://jurnal.umus.ac.id/index.php/intech/article/view/556 

Jika kamu memanfaatkan repositori ini dalam publikasi akademis, kami sangat mengapresiasi sitasi ke paper berikut:

    @article{j.ilm.intech:v03:02-556,
    author  = {Wildan Fariq Abdillah, Agyztia Premana, Raden Mohamad Herdian Bhakti},
    title   = {Analisis Sentimen Penanganan Covid-19 dengan Support Vector Machine: Evaluasi Leksikon dan Metode Ekstraksi Fitur},
    journal = {Jurnal Ilmiah Intech: Information Technology Journal of UMUS},
    year    = {2021},
    volume  = {03},
    issue   = {02},
    pages   = {160-170},
    issn    = {2685-4902 (online)},
    doi     = {10.46772/intech.v3i02.556},
    url     = {http://jurnal.umus.ac.id/index.php/intech/article/download/556/373}
    }

## to-dos
- [x] jupyter notebooks (ipynb) + petunjuk bahasa Indonesia
- [x] jupyter notebooks (ipynb) + English guide
- [ ] plotting refinement or addition
- [ ] implement **sentistrength_id** as whole, including question word, negation handling, etc.
- [ ] spell check: [checker_id](https://github.com/mamat-rahmat/checker_id), [stif-indonesia](https://github.com/haryoa/stif-indonesia), [Peter Norvig's](https://norvig.com/spell-correct.html), [spellchecker](https://github.com/pirate/spellchecker), [SymSpell](https://github.com/wolfgarbe/SymSpell).
- [ ] <del>stemmer/lemmatizer: [PySastrawi](https://github.com/har07/PySastrawi), [nlp-id](https://github.com/kumparan/nlp-id)</del>
- [ ] python code coverage

## Bacaan Lanjut
- https://github.com/louisowen6/NLP_bahasa_resources
- https://github.com/makcedward/nlp
- https://github.com/keon/awesome-nlp
