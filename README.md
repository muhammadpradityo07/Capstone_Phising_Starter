# Capstone Kelompok 3 — Deteksi URL Phishing

Starter aplikasi web Streamlit yang menggunakan model Random Forest dan ekstraksi 22 fitur dari notebook `Capstone_Project_Kelompok_3.ipynb`.

## Isi folder

- `app.py` — aplikasi Streamlit
- `requirements.txt` — dependensi Python
- `random_forest_phishing.pkl` — **harus ditambahkan dari Google Colab**
- `feature_columns.pkl` — **harus ditambahkan dari Google Colab**

File model `.pkl` tidak disertakan di paket ini karena artefak tersebut perlu diunduh dari sesi Google Colab milik kelompok.

## 1. Unduh model dari Google Colab

1. Buka notebook Kelompok 3.
2. Jalankan cell yang menyimpan model Random Forest dan `feature_columns.pkl` (cell dengan `joblib.dump`).
3. Jalankan cell berikutnya yang memanggil `files.download(...)` untuk mengunduh kedua file.
4. Pindahkan kedua file ke folder yang sama dengan `app.py`.

Sebelum deploy, cek versi scikit-learn di notebook dengan:

```python
import sklearn
print(sklearn.__version__)
```

Untuk menghindari masalah kompatibilitas file model pickle/joblib, ganti baris `scikit-learn` di `requirements.txt` dengan versi yang sama persis, misalnya `scikit-learn==X.Y.Z` menggunakan angka versi yang benar-benar tercetak di Colab.

## 2. Jalankan di Windows

Pastikan Python terpasang. Buka Command Prompt di folder ini, lalu jalankan:

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Browser akan membuka aplikasi lokal Streamlit. Jika perintah `python` tidak dikenali, coba gunakan launcher `py` pada perintah pembuatan virtual environment dan instalasi.

## 3. Tes dasar

Coba beberapa input untuk memastikan aplikasi merespons dengan benar:

- `https://www.rmit.edu.au/`
- URL contoh dari kelas legitimate pada dataset
- URL phishing dari dataset (jangan dibuka di browser; cukup ditempelkan sebagai teks)
- input kosong
- `bukan url`

Untuk uji prediksi yang terukur, gunakan sampel berlabel dari data test dan catat apakah prediksinya sesuai label aktual. Contoh URL saja tidak menjamin bahwa model akan selalu tepat.

## 4. GitHub dan deploy

Setelah aplikasi bekerja lokal:

1. Buat repository GitHub untuk aplikasi.
2. Push `app.py`, `requirements.txt`, dan file model serta daftar fitur yang dibutuhkan.
3. Buka <https://share.streamlit.io>, masuk menggunakan GitHub, pilih **Create app**, lalu tentukan repository, branch, dan `app.py` sebagai entrypoint.
4. Deploy, lalu uji URL aplikasi yang terbit.

**Catatan:** file `.pkl` menyimpan model hasil training. Hanya unggah model dari notebook kelompok sendiri dan jangan memuat file pickle dari sumber yang tidak dipercaya.
