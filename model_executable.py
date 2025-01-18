#!/usr/bin/env python3

import joblib
import pandas as pd
from urllib.parse import urlparse

from utils.features_extractors import (
    extract_feature_count_dash,
    extract_feature_count_percent,
    extract_feature_directory_num,
    extract_feature_dot_number,
    extract_feature_embed_domain_number,
    extract_feature_first_directory_length,
    extract_feature_has_http,
    extract_feature_has_https,
    extract_feature_hostname_length,
    extract_feature_ip_use,
    extract_feature_is_shortened,
    extract_feature_num_at_signs,
    extract_feature_num_digits,
    extract_feature_num_fragments,
    extract_feature_num_letters,
    extract_feature_num_percent20,
    extract_feature_num_query_parameters,
    extract_feature_num_subdomains,
    extract_feature_num_www,
    extract_feature_suspiciousurl,
    extract_feature_top_level_domain_length,
    extract_feature_url_entropy,
)

FEATURE_ORDER = [
    'ip_use',
    'url_entropy',
    'num_digits',
    'num_query_parameters',
    'num_fragments',
    'num_percent20',
    'num_at_signs',
    'has_http',
    'has_https',
    'dot_number',
    'num_www',
    'directory_num',
    'embed_domain_number',
    'suspiciousurl',
    'count_percent',
    'count_dash',
    'is_shortened',
    'hostname_length',
    'first_directory_length',
    'top_level_domain_length',
    'num_letters',
    'num_subdomains'
]

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc)

def extract_features(url):
    return {
        'ip_use': extract_feature_ip_use(url),
        'url_entropy': extract_feature_url_entropy(url),
        'num_digits': extract_feature_num_digits(url),
        'num_query_parameters': extract_feature_num_query_parameters(url),
        'num_fragments': extract_feature_num_fragments(url),
        'num_percent20': extract_feature_num_percent20(url),
        'num_at_signs': extract_feature_num_at_signs(url),
        'has_http': extract_feature_has_http(url),
        'has_https': extract_feature_has_https(url),
        'dot_number': extract_feature_dot_number(url),
        'num_www': extract_feature_num_www(url),
        'directory_num': extract_feature_directory_num(url),
        'embed_domain_number': extract_feature_embed_domain_number(url),
        'suspiciousurl': extract_feature_suspiciousurl(url),
        'count_percent': extract_feature_count_percent(url),
        'count_dash': extract_feature_count_dash(url),
        'is_shortened': extract_feature_is_shortened(url),
        'hostname_length': extract_feature_hostname_length(url),
        'first_directory_length': extract_feature_first_directory_length(url),
        'top_level_domain_length': extract_feature_top_level_domain_length(url),
        'num_letters': extract_feature_num_letters(url),
        'num_subdomains': extract_feature_num_subdomains(url)
    }

def predict_url(url, model_path='random_forest_model.joblib'):
    model = joblib.load(model_path)
    features_dict = extract_features(url)
    row = [features_dict[col] for col in FEATURE_ORDER]
    features_df = pd.DataFrame([row], columns=FEATURE_ORDER)
    prediction = model.predict(features_df)
    return prediction[0]


if __name__ == "__main__":
    url = input("Enter the URL to analyze: ")
    
    try:
        result = predict_url(url)
        print(f"> Prediction for {url}: {result}")
    except Exception as e:
        print(f"[!] Error occurred: {str(e)}")
