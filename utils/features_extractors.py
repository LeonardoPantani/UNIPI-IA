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

def extract_feature_num_letters(url: str) -> int:
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

def extract_feature_has_http(url: str) -> int:
    return 1 if url.lower().startswith('http://') else 0

def extract_feature_has_https(url: str) -> int:
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

# Corretta: Conta i domini "embeddati" contando i domini e non gli schemi
def extract_feature_embed_domain_number(url: str) -> int:
    parsed_url = urlparse(url)
    # Considero solo la parte del percorso e della query
    path_and_query = parsed_url.path
    if parsed_url.query:
        path_and_query += "?" + parsed_url.query
    
    # Trovo tutti i domini "embeddati" usando una regex
    embedded_domains = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', path_and_query)
    
    return len(embedded_domains)

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
    return int(bool(re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adataset\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)))

def extract_feature_hostname_length(url: str) -> int:
    parsed = urlparse(url)
    return len(parsed.netloc)

# Corretta: Calcola la lunghezza del primo segmento del path
def extract_feature_first_directory_length(url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == '/':
        return 0

    segments = path.split('/')
    # Rimuovi segmenti vuoti causati da slash multipli o slash finali
    segments = [s for s in segments if s]

    if not segments:
        return 0
    
    return len(segments[0])

def extract_feature_top_level_domain_length(url: str) -> int:
    parsed = urlparse(url)
    hostname = parsed.netloc
    if '.' not in hostname:
        return 0

    parts = hostname.split('.')
    tld = parts[-1]
    return len(tld)

# Nuova funzione: Calcola il numero di sottodomini
def extract_feature_num_subdomains(url: str) -> int:
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    # Rimuovi 'www.' se presente per evitare di contarlo come sottodominio
    hostname = hostname.lstrip('www.')
    return hostname.count('.')