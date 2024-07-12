import pandas as pd
import requests
import zipfile
import gzip
import shutil
import io
import csv
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re
import time
import random
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
import whois
import socket
from datetime import datetime

# Download and process Tranco list
def get_tranco_data():
    url = "https://tranco-list.eu/top-1m.csv.zip"
    response = requests.get(url)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
        with zip_ref.open('top-1m.csv') as csv_file:
            tranco_df = pd.read_csv(csv_file, names=['rank', 'domain'])
    return dict(zip(tranco_df['domain'], tranco_df['rank']))

# Download and process Majestic Million
def get_majestic_data():
    url = "https://downloads.majestic.com/majestic_million.csv"
    response = requests.get(url)
    majestic_dict = {}
    for row in csv.reader(io.StringIO(response.text)):
        if row[0] != 'GlobalRank':  # Skip header
            majestic_dict[row[2]] = int(row[0])
    return majestic_dict

# Download and process PhishTank data
def get_phishtank_data():
    url = "http://data.phishtank.com/data/online-valid.csv.gz"
    response = requests.get(url)
    
    if 'exceeded the request rate limit' in response.text:
        print("PhishTank rate limit exceeded. Using a dummy dataset.")
        return pd.DataFrame({'url': [f'http://phishing-example-{i}.com' for i in range(10000)]})
    
    if response.content[:2] == b'\x1f\x8b':  # Gzip magic number
        with gzip.open(io.BytesIO(response.content), 'rt') as f:
            return pd.read_csv(f)
    else:
        print("Warning: The downloaded file is not in gzip format.")
        print("First few bytes:", response.content[:20])
        print("Attempting to read as plain CSV...")
        df = pd.read_csv(io.StringIO(response.text))
        if 'url' not in df.columns:
            print("'url' column not found. Using the first column as URL.")
            df = df.rename(columns={df.columns[0]: 'url'})
        return df

# Feature extraction function
def feature_extraction(url, label, tranco_dict, majestic_dict):
    features = {}
    parsed_url = urlparse(url)
    
    # Domain of the URL
    features['Domain'] = parsed_url.netloc
    
    # IP Address in the URL
    features['Have_IP'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc) else 0
    
    # "@" Symbol in URL
    features['Have_At'] = 1 if '@' in url else 0
    
    # URL Length
    features['URL_Length'] = 1 if len(url) >= 54 else 0
    
    # URL Depth
    features['URL_Depth'] = len([x for x in parsed_url.path.split('/') if x])
    
    # Presence of "http/https" in Domain
    features['https_Domain'] = 1 if re.search(r"https?://", parsed_url.netloc) else 0
    
    # URL Shortening Services
    shortening_services = ["bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl"]
    features['TinyURL'] = 1 if any(service in parsed_url.netloc for service in shortening_services) else 0
    
    # Presence of "-" in Domain
    features['Prefix/Suffix'] = 1 if '-' in parsed_url.netloc else 0
    
    # DNS Record
    try:
        domain = whois.whois(parsed_url.netloc)
        features['DNS_Record'] = 0 if domain.domain_name else 1
    except:
        features['DNS_Record'] = 1
    
    # Web Traffic
    rank = min(tranco_dict.get(parsed_url.netloc, float('inf')), majestic_dict.get(parsed_url.netloc, float('inf')))
    features['Web_Traffic'] = 0 if rank < 100000 else 1
    
    # End Period of Domain
    try:
        domain = whois.whois(parsed_url.netloc)
        if isinstance(domain.expiration_date, list):
            expiration_date = domain.expiration_date[0]
        else:
            expiration_date = domain.expiration_date
        end_period = (expiration_date - datetime.now()).days
        features['Domain_End'] = 0 if end_period <= 180 else 1
    except:
        features['Domain_End'] = 1
    
    # Web content-based features
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    try:
        response = requests.get(url, timeout=5, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # IFrame Redirection
            features['iFrame'] = 1 if soup.find_all('iframe', frameborder=0) else 0
            
            # Status Bar Customization
            features['Mouse_Over'] = 1 if soup.find_all('a', onmouseover=True) else 0
            
            # Disabling Right Click
            features['Right_Click'] = 1 if 'event.button==2' in response.text else 0
            
            # Website Forwarding
            features['Web_Forwards'] = 1 if len(response.history) >= 4 else 0
            
        else:
            features['iFrame'] = features['Mouse_Over'] = features['Right_Click'] = features['Web_Forwards'] = 0
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
        features['iFrame'] = features['Mouse_Over'] = features['Right_Click'] = features['Web_Forwards'] = 0
    
    # Adding the label
    features['Label'] = label
    
    return features

def feature_extraction_with_retry(url, label, tranco_dict, majestic_dict, max_retries=3):
    for attempt in range(max_retries):
        try:
            return feature_extraction(url, label, tranco_dict, majestic_dict)
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"Error processing URL {url} after {max_retries} attempts: {str(e)}")
                return None
            time.sleep(random.uniform(1, 3))  # Random delay between retries

def process_url(url, label, tranco_dict, majestic_dict):
    return feature_extraction_with_retry(url, label, tranco_dict, majestic_dict)

def parallel_feature_extraction(urls, label, tranco_dict, majestic_dict, desc):
    features = []
    with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count() * 2) as executor:
        future_to_url = {executor.submit(process_url, url, label, tranco_dict, majestic_dict): url for url in urls}
        for future in tqdm(as_completed(future_to_url), total=len(urls), desc=desc):
            url = future_to_url[future]
            try:
                feature = future.result()
                if feature is not None:
                    features.append(feature)
            except Exception as exc:
                print(f'{url} generated an exception: {exc}')
    return features

if __name__ == "__main__":
    print("Downloading and processing data...")
    tranco_dict = get_tranco_data()
    majestic_dict = get_majestic_data()
    
    try:
        phish_data = get_phishtank_data()
        print(f"PhishTank data shape: {phish_data.shape}")
        print(f"PhishTank data columns: {phish_data.columns}")
    except Exception as e:
        print(f"Error processing PhishTank data: {str(e)}")
        print("Proceeding with a dummy phishing dataset...")
        phish_data = pd.DataFrame({'url': [f'http://phishing-example-{i}.com' for i in range(10000)]})

    # Combine Tranco and Majestic Million domains
    all_domains = list(set(tranco_dict.keys()) | set(majestic_dict.keys()))

    # Randomly select 5000 domains
    random_domains = random.sample(all_domains, 5000)

    # Create a DataFrame with these domains
    random_legiturl = pd.DataFrame({'URLs': ['http://' + domain for domain in random_domains]})

    # Randomly sample 5000 phishing URLs
    random_phishurl = phish_data.sample(n=min(5000, len(phish_data)), random_state=12)[['url']]

    print("Extracting features...")
    legit_features = parallel_feature_extraction(random_legiturl['URLs'], 0, tranco_dict, majestic_dict, "Extracting legitimate URL features")
    phish_features = parallel_feature_extraction(random_phishurl['url'], 1, tranco_dict, majestic_dict, "Extracting phishing URL features")

    # Combine features into DataFrames
    legit_df = pd.DataFrame(legit_features)
    phish_df = pd.DataFrame(phish_features)
    all_features_df = pd.concat([legit_df, phish_df], ignore_index=True)

    print("Saving results...")
    # Save the results
    all_features_df.to_csv('phishing_detection_dataset.csv', index=False)

    print(f"Dataset saved as 'phishing_detection_dataset.csv'")
    print(f"Shape of final dataset: {all_features_df.shape}")