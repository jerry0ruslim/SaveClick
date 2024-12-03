from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf
import numpy as np
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.optimizers import Adam
import pickle
import json
import tldextract
from scipy.stats import entropy
import re
import whois
from datetime import datetime
import traceback
import pandas as pd

class FeatureExtractor:
    def __init__(self): # Extract Domain
        self.tld_extractor = tldextract.TLDExtract(cache_dir=False)
    
    def url_length(self, url: str) -> int:
        return len(url)
    
    def url_entropy(self, url: str) -> float: # URL Shannon entropy
        try:
            char_count = {}
            for c in url:
                char_count[c] = char_count.get(c, 0) + 1
            length = len(url)
            probabilities = [count/length for count in char_count.values()]
            return entropy(probabilities, base=2)
        except Exception as e:
            print(f"Error calculating entropy: {e}")
            return 0.0
    
    def digit_letter_ratio(self, url: str) -> float:
        try:
            digits = sum(c.isdigit() for c in url)
            letters = sum(c.isalpha() for c in url)
            return digits / letters if letters > 0 else 0.0
        except:
            return 0.0
    
    def count_special_chars(self, url: str, char: str) -> int:
        return url.count(char)
    
    def tld_count(self, url: str) -> int:
        # Regular expression to find TLDs in the URL (including subdomains and paths)
        common_tlds = [
            # Top-level domains
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'biz', 'info', 'name', 'pro', 'museum', 'coop', 'aero', 'xxx', 'idn',
            
            # Country-code TLDs
            'us', 'uk', 'ca', 'de', 'jp', 'fr', 'it', 'es', 'ru', 'cn', 'br', 'au', 'in', 'ch', 'nl', 'se', 'no', 'pl', 'ir', 'at', 'be', 'dk', 'ar', 'mx', 'tw', 'vn', 'tr', 'cu', 'cl', 'ro', 'ph', 'ie', 'th', 'za', 'sg', 'my', 'co', 'id', 'nz', 'sk', 'cz', 'hu', 'gr', 'pt', 'il', 'pk', 'ae', 'eg', 'hk', 'si', 'bg', 'ua', 'kr', 'ma', 'kz', 'rs', 'sa', 'lt', 'ee', 'lv', 'hr', 'cy', 'pe', 'ec', 'bo', 'pa',
            
            # Multi-level TLDs
            'co.uk', 'com.au', 'org.uk', 'ac.uk', 'gov.uk', 'sch.uk', 'mod.uk', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz', 'ac.nz', 'govt.nz', 'mil.nz', 'co.id', 'ac.id', 'co.in', 'ac.in', 'nic.in', 'res.in', 'gov.in', 'mil.in',
        ]
        # Split the URL
        url_parts = url.split('/')
        
        common_tld_count = 0
        for part in url_parts:
            if '.' in part:
                tld = part.split('.')[-1]
                if tld in common_tlds:
                    common_tld_count += 1
        
        if common_tld_count == 0:
            common_tld_count = 0
        else:
            common_tld_count -= 1
        
        return common_tld_count
    
    def subdomain_count(self, url: str) -> int:
        try:
            return len(self.tld_extractor(url).subdomain.split('.'))
        except:
            return 0
    
    def nan_char_entropy(self, url: str) -> float:
        try:
            nan_chars = [c for c in url if not c.isalnum()]
            if not nan_chars:
                return 0.0
            prob = [float(nan_chars.count(c)) / len(nan_chars) for c in dict.fromkeys(nan_chars)]
            return entropy(prob)
        except:
            return 0.0
# python accuracy_checker.py data_phishing_37175.json data_legitimate_36400.json
# python accuracy_checker.py phishing_sample.json legitimate_sample.json
    def domain_age_days(self, url: str) -> int:
        # return -1
        try:
            domain = self.tld_extractor(url).registered_domain
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                return (datetime.now() - creation_date).days
            return -1
        except:
            return -1
    
    def starts_with_ip(self, url: str) -> bool:
        pattern = r'^(http://|https://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.match(pattern, url))
    
    def has_punycode(self, url: str) -> bool: # münich.com
        return 'xn--' in url.lower()
    
    def domain_has_digits(self, url: str) -> bool:
        try:
            domain = self.tld_extractor(url).domain
            return any(char.isdigit() for char in domain)
        except:
            return False
    
    def has_internal_links(self, url: str) -> bool:
        return '#' in url

    def extract_features(self, url: str) -> dict:
        return {
            'url_length': self.url_length(url),
            'url_entropy': self.url_entropy(url),
            'digit_letter_ratio': self.digit_letter_ratio(url),
            'dot_count': self.count_special_chars(url, '.'),
            'at_count': self.count_special_chars(url, '@'),
            'dash_count': self.count_special_chars(url, '-'),
            'tld_count': self.tld_count(url),
            'subdomain_count': self.subdomain_count(url),
            'nan_char_entropy': self.nan_char_entropy(url),
            'domain_age_days': self.domain_age_days(url),
            'starts_with_ip': int(self.starts_with_ip(url)),
            'has_punycode': int(self.has_punycode(url)),
            'domain_has_digits': int(self.domain_has_digits(url)),
            'has_internal_links': int(self.has_internal_links(url))
        }

def load_model_with_verification(model_path):
    model = load_model(model_path, compile=False)
    
    # Compile with same settings as training
    optimizer = Adam(learning_rate=0.001)
    model.compile(
        optimizer=optimizer,
        loss='binary_crossentropy',
        metrics=['accuracy', tf.keras.metrics.AUC()]
    )
    
    for layer in model.layers:
        weights = layer.get_weights()
        if weights:
            return model

class URLClassifier:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.feature_extractor = FeatureExtractor()
        self.MAX_LEN = 100
        self.feature_order = [
            'url_length', 'url_entropy', 'digit_letter_ratio', 'dot_count', 
            'at_count', 'dash_count', 'tld_count', 'subdomain_count', 
            'nan_char_entropy', 'domain_age_days', 'starts_with_ip', 
            'has_punycode', 'domain_has_digits', 'has_internal_links'
        ]

    def load_model(self):
        """Load tokenizer and model"""
        try:
            with open('tokenizer.pickle', 'rb') as handle:
                self.tokenizer = pickle.load(handle)
            print("✓ Tokenizer loaded successfully")
            
            self.model = load_model_with_verification('url_classifier_model.h5')
            print("✓ Model loaded successfully")
            
            return True
            
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            traceback.print_exc()
            return False

    def preprocess_url(self, url: str) -> "tuple":
        # Remove http:// or https:// consistently
        processed_url = url.replace('http://', '').replace('https://', '')
        if processed_url.endswith('/'):
            processed_url = processed_url[:-1]
        # Create sequence tensor
        url_seq = self.tokenizer.texts_to_sequences([processed_url])
        padded_seq = pad_sequences(url_seq, maxlen=self.MAX_LEN, padding='post', truncating='post')
        url_tensor = tf.convert_to_tensor(padded_seq, dtype=tf.float32)
        
        return processed_url, url_tensor


    def extract_features(self, url: str) -> tf.Tensor:
        features = self.feature_extractor.extract_features(url)
        features_df = pd.DataFrame([features])
        ordered_features = features_df[self.feature_order]
        ordered_features = ordered_features.fillna(0)
        return tf.convert_to_tensor(ordered_features.values, dtype=tf.float32)

    def predict(self, url: str) -> dict:
        try:
            # Set learning phase to 0 (test)
            tf.keras.backend.set_learning_phase(0)
            
            # Preprocess URL for both features and sequences
            processed_url, url_input = self.preprocess_url(url)
            
            # Extract features using the processed URL
            features = self.feature_extractor.extract_features(processed_url)
            features_input = tf.convert_to_tensor(
                pd.DataFrame([features])[self.feature_order].fillna(0).values, 
                dtype=tf.float32
            )

            # Make prediction
            prediction = self.model([url_input, features_input], training=False)
            prediction_value = float(prediction.numpy()[0][0])
            
            # Debug output
            print("\nPrediction Results:")
            print("-" * 50)
            print(f"URL: {url}")
            print(f"Prediction score: {prediction_value:.4f}")
            print(f"Classification: {'Phishing' if prediction_value > 0.5 else 'Legitimate'}")
            
            print("\nExtracted Features:")
            for feature, value in sorted(features.items()):
                print(f"{feature}: {value}")

            return {
                'input_url': url,
                'processed_url':processed_url,
                'score': prediction_value,
                'is_phishing': prediction_value > 0.5,
                'confidence': max(prediction_value, 1-prediction_value) * 100,
                'features': features
            }

        except Exception as e:
            print(f"Prediction error: {str(e)}")
            traceback.print_exc()
            raise

# Flask application setup
app = Flask(__name__)
CORS(app)

# Global classifier instance
classifier = None

def initialize_classifier():
    """Initialize the URL classifier"""
    global classifier
    try:
        classifier = URLClassifier()
        return classifier.load_model()
    except Exception as e:
        print(f"Error initializing classifier: {str(e)}")
        return False

@app.route('/scan', methods=['POST'])
def scan_url():
    """Endpoint to scan URLs"""
    global classifier
    
    if classifier is None:
        success = initialize_classifier()
        if not success:
            return jsonify({'error': 'Failed to initialize classifier'}), 500
    
    try:
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
            
        result = classifier.predict(url)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500
    
if __name__ == '__main__':
    if initialize_classifier():
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Failed to initialize classifier. Exiting...")