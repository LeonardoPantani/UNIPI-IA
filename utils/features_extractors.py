import re
import math
from urllib.parse import urlparse, parse_qs

def extract_feature_ip_use(url: str) -> int:
    ipv4_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    ipv6_pattern = r'([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}'

    if re.search(ipv4_pattern, url) or re.search(ipv6_pattern, url):
        return 1
    return 0

def extract_feature_url_entropy(url: str) -> float:
    if not url:
        return 0.0

    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0.0
    n = len(url)
    for c in freq:
        p = freq[c] / n
        entropy -= p * math.log2(p)

    return entropy

def extract_feature_num_digits(url: str) -> int:
    return sum(c.isdigit() for c in url)

def extract_feature_letter_count(url: str) -> int:
    return sum(c.isalpha() for c in url)

def extract_feature_url_length(url: str) -> int:
    return len(url)

def extract_feature_num_query_parameters(url: str) -> int:
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    return len(query_params)

def extract_feature_num_fragments(url: str) -> int:
    return url.count('#')

def extract_feature_num_percent20(url: str) -> int:
    return url.count('%20')

def extract_feature_num_at_signs(url: str) -> int:
    return url.count('@')

def extract_feature_hashttp(url: str) -> int:
    return 1 if url.lower().startswith('http://') else 0

def extract_feature_hashttps(url: str) -> int:
    return 1 if url.lower().startswith('https://') else 0

def extract_feature_dot_number(url: str) -> int:
    return url.count('.')

def extract_feature_num_www(url: str) -> int:
    return url.lower().count('www')

def extract_feature_directory_num(url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path
    path_parts = [p for p in path.split('/') if p]
    return len(path_parts)

def extract_feature_embed_domain_number(url: str) -> int:
    pattern = r'(?:http://|https://)'
    matches = re.findall(pattern, url.lower())
    return len(matches)

def extract_feature_suspiciousurl(url: str) -> int:
    suspicious_words = [
        'Paypal', 'bank', 'credit', 'login', 'confirm',
        'free', 'lucky', 'prize', 'amazon', 'secure',
        'verification', 'account', 'update', 'ebay',
        'appleid', 'gift', 'win', 'bonus', 'btc', 'bitcoin','login','account','service','bonus'
    ]
    url_lower = url.lower()
    for word in suspicious_words:
        if word in url_lower:
            return 1
    return 0

def extract_feature_count_percent(url: str) -> int:
    return url.count('%')

def extract_feature_count_dash(url: str) -> int:
    return url.count('-')

def extract_feature_count_equal(url: str) -> int:
    return url.count('=')

def extract_feature_is_shortened(url: str) -> int:
    return int(bool(re.search(r'bit\.ly|t\.co|ow\.ly', url)))

def extract_feature_hostname_length(url: str) -> int:
    parsed = urlparse(url)
    return len(parsed.netloc)

def extract_feature_first_directory_length(url: str) -> int:
    parsed = urlparse(url)
    if parsed.path.startswith('/'):
        scheme_part = f"{parsed.scheme}://"
        start_of_path_index = url.find('/', len(scheme_part + parsed.netloc))
        if start_of_path_index == -1:
            return 0
        else:
            return start_of_path_index
    return 0

def extract_feature_top_level_domain_length(url: str) -> int:
    parsed = urlparse(url)
    hostname = parsed.netloc
    if '.' not in hostname:
        return 0

    parts = hostname.split('.')
    tld = parts[-1]
    return len(tld)