import joblib
import requests
from urllib.parse import urlparse
import re
import numpy as np
from utils.features_extractors import (
    extract_feature_ip_use, extract_feature_url_entropy, extract_feature_num_digits,
    extract_feature_num_query_parameters, extract_feature_num_fragments, extract_feature_num_percent20,
    extract_feature_num_at_signs, extract_feature_has_http, extract_feature_has_https,
    extract_feature_dot_number, extract_feature_num_www, extract_feature_directory_num,
    extract_feature_suspiciousurl, extract_feature_count_percent, extract_feature_count_dash,
    extract_feature_is_shortened, extract_feature_hostname_length, extract_feature_top_level_domain_length,
    extract_feature_num_letters, extract_feature_first_directory_length, extract_feature_num_subdomains,extract_feature_embed_domain_number
)

def extract_features(url):
    parsed = urlparse(url)
    
    features = {
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
        'suspiciousurl': extract_feature_suspiciousurl(url),
        'count_percent': extract_feature_count_percent(url),
        'count_dash': extract_feature_count_dash(url),
        'is_shortened': extract_feature_is_shortened(url),
        'hostname_length': extract_feature_hostname_length(url),
        'top_level_domain_length': extract_feature_top_level_domain_length(url),
        'num_letters': extract_feature_num_letters(url),
        'first_directory_length': extract_feature_first_directory_length(url),
        'num_subdomains': extract_feature_num_subdomains(url),
        'embed_domain': extract_feature_embed_domain_number(url)
    }
    
    return np.array([list(features.values())])

def predict_url(url, model_path='random_forest_model.joblib'):
    try:
        # Load the model
        model = joblib.load(model_path)
        
        # Extract features from URL
        features = extract_features(url)
        
        # Make prediction
        prediction = model.predict(features)
        
        return prediction[0]
    
    except Exception as e:
        return f"Error occurred: {str(e)}"

if __name__ == "__main__":
    # Example usage
    test_url = input("Enter the URL to analyze: ")
    result = predict_url(test_url)
    print(f"Prediction for {test_url}: {result}")