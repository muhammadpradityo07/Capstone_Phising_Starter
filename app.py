from __future__ import annotations

import ipaddress
import math
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
import streamlit as st
import tldextract

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "random_forest_phishing.pkl"
FEATURES_PATH = BASE_DIR / "feature_columns.pkl"

EXPECTED_FEATURES = [
    "url_len", "dom_len", "is_ip", "tld_len", "subdom_cnt",
    "letter_cnt", "digit_cnt", "special_cnt", "eq_cnt", "qm_cnt",
    "amp_cnt", "dot_cnt", "dash_cnt", "under_cnt", "letter_ratio",
    "digit_ratio", "spec_ratio", "is_https", "slash_cnt",
    "entropy", "path_len", "query_len",
]

st.set_page_config(
    page_title="Deteksi URL Phishing",
    page_icon="🛡️",
    layout="centered",
)


@st.cache_resource
def load_model_and_features():
    """Load the artifacts exported from the group's Colab notebook."""
    if not MODEL_PATH.exists() or not FEATURES_PATH.exists():
        missing = []
        if not MODEL_PATH.exists():
            missing.append(MODEL_PATH.name)
        if not FEATURES_PATH.exists():
            missing.append(FEATURES_PATH.name)
        raise FileNotFoundError(
            "File model belum tersedia: " + ", ".join(missing)
        )

    model = joblib.load(MODEL_PATH)
    features = joblib.load(FEATURES_PATH)

    if list(features) != EXPECTED_FEATURES:
        raise ValueError(
            "Daftar fitur pada feature_columns.pkl tidak sama dengan "
            "urutan 22 fitur yang diharapkan aplikasi. Pastikan artefak "
            "berasal dari notebook final yang sama."
        )
    return model, list(features)


def normalize_url(raw_url: str) -> str:
    """Validate the input and add http:// if the user omitted a scheme."""
    value = raw_url.strip()
    if not value:
        raise ValueError("Masukkan URL terlebih dahulu.")
    if any(ch.isspace() for ch in value):
        raise ValueError("URL tidak boleh mengandung spasi. Periksa kembali input.")

    parsed = urlparse(value if "://" in value else "http://" + value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Gunakan URL dengan skema http:// atau https://.")
    if not parsed.hostname:
        raise ValueError("Format URL belum valid. Contoh: https://example.com/login")

    # Training data URLs normally include http:// or https://.
    return value if "://" in value else "http://" + value


def extract_url_features(url: str) -> dict[str, float | int]:
    """Extract the same 22 URL features used in the provided notebook."""
    url = str(url).strip()
    parsed_url = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed_url.hostname or ""

    # Use the same tldextract behavior as the notebook's feature extractor.
    ext = tldextract.extract(hostname)
    domain = (
        f"{ext.domain}.{ext.suffix}"
        if ext.domain and ext.suffix
        else ext.domain or hostname
    )
    tld = ext.suffix

    url_len = len(url)
    letter_cnt = sum(ch.isalpha() for ch in url)
    digit_cnt = sum(ch.isdigit() for ch in url)
    special_cnt = sum(not ch.isalnum() for ch in url)

    letter_ratio = letter_cnt / url_len if url_len else 0.0
    digit_ratio = digit_cnt / url_len if url_len else 0.0
    spec_ratio = special_cnt / url_len if url_len else 0.0

    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    counts = Counter(url)
    entropy = (
        -sum(
            (count / url_len) * math.log2(count / url_len)
            for count in counts.values()
        )
        if url_len
        else 0.0
    )

    path_len = len(parsed_url.path)
    query_len = len(parsed_url.query)

    return {
        "url_len": url_len,
        "dom_len": len(domain),
        "is_ip": is_ip,
        "tld_len": len(tld),
        "subdom_cnt": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "letter_cnt": letter_cnt,
        "digit_cnt": digit_cnt,
        "special_cnt": special_cnt,
        "eq_cnt": url.count("="),
        "qm_cnt": url.count("?"),
        "amp_cnt": url.count("&"),
        "dot_cnt": url.count("."),
        "dash_cnt": url.count("-"),
        "under_cnt": url.count("_"),
        "letter_ratio": letter_ratio,
        "digit_ratio": digit_ratio,
        "spec_ratio": spec_ratio,
        "is_https": int(parsed_url.scheme.lower() == "https"),
        "slash_cnt": url.count("/"),
        "entropy": entropy,
        "path_len": path_len,
        "query_len": query_len,
    }


def predict_url(url: str, model, feature_columns: list[str]):
    extracted = extract_url_features(url)
    input_df = pd.DataFrame([extracted]).reindex(columns=feature_columns)
    prediction = int(model.predict(input_df)[0])

    confidence = None
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(input_df)[0]
        classes = list(model.classes_)
        probability_by_class = {
            int(cls): float(prob)
            for cls, prob in zip(classes, probabilities)
        }
        confidence = probability_by_class.get(prediction)

    return prediction, confidence, extracted


st.title("🛡️ Sistem Deteksi URL Phishing")
st.write(
    "Prototype screening awal URL berbasis Machine Learning untuk membantu "
    "staf atau admin UMKM memeriksa tautan sebelum membukanya."
)
st.info(
    "Aplikasi ini hanya menganalisis karakteristik URL. Aplikasi tidak membuka "
    "atau mengunjungi URL yang diperiksa. Hasil prediksi bukan jaminan mutlak "
    "bahwa sebuah situs aman atau berbahaya."
)

try:
    model, feature_columns = load_model_and_features()
except Exception as exc:
    st.error("Model belum dapat dimuat.")
    st.write(str(exc))
    st.markdown(
        "**Langkah perbaikan:** jalankan cell penyimpanan model di Google Colab, "
        "unduh `random_forest_phishing.pkl` dan `feature_columns.pkl`, lalu letakkan "
        "kedua file itu di folder yang sama dengan `app.py`."
    )
    st.stop()

with st.form("url_check_form"):
    user_url = st.text_input(
        "URL yang ingin diperiksa",
        placeholder="Contoh: https://example.com/login",
        help="Jangan buka tautan yang mencurigakan. Cukup tempelkan alamatnya di sini.",
    )
    submitted = st.form_submit_button("Periksa URL", type="primary", use_container_width=True)

if submitted:
    try:
        normalized_url = normalize_url(user_url)
        prediction, confidence, extracted_features = predict_url(
            normalized_url, model, feature_columns
        )

        st.subheader("Hasil pemeriksaan")
        st.code(normalized_url, language=None)

        if prediction == 1:
            st.error("⚠️ Model mengklasifikasikan URL ini sebagai PHISHING.")
            st.write(
                "Hindari memasukkan kata sandi, kode OTP, atau informasi pribadi "
                "pada situs tersebut. Verifikasi alamat melalui kanal resmi."
            )
        else:
            st.success("Model mengklasifikasikan URL ini sebagai LEGITIMATE.")
            st.write(
                "URL tidak terindikasi phishing berdasarkan pola yang dipelajari "
                "model. Ini tidak berarti situs pasti aman; tetap periksa sumber "
                "tautan dan nama domainnya."
            )

        if confidence is not None:
            st.metric("Skor keyakinan model", f"{confidence * 100:.2f}%")
            st.caption(
                "Skor ini berasal dari probabilitas keluaran Random Forest, "
                "bukan jaminan keamanan dan belum tentu merupakan probabilitas "
                "risiko yang terkalibrasi."
            )

        with st.expander("Lihat 22 fitur URL yang dianalisis"):
            feature_table = pd.DataFrame(
                {"Fitur": feature_columns,
                 "Nilai": [extracted_features[name] for name in feature_columns]}
            )
            st.dataframe(feature_table, hide_index=True, use_container_width=True)

    except ValueError as exc:
        st.warning(str(exc))
    except Exception as exc:
        st.error("Terjadi kendala saat memproses URL.")
        st.caption(f"Detail teknis: {exc}")

st.divider()
st.caption(
    "Capstone Project Kelompok 3 · Model Random Forest · "
    "Hanya untuk screening awal, bukan pengganti layanan keamanan khusus."
)
