import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import hashlib
import requests
import secrets
import string
import math
import random

app = Flask(__name__)
CORS(app)

# --- SERVE FRONTEND ---
@app.route('/')
def index():
    # This fixes the 404 error by serving index.html from the same directory
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'index.html')

def check_pwned_api(password):
    """Checks HaveIBeenPwned API securely."""
    try:
        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        head, tail = sha1password[:5], sha1password[5:]
        url = f'https://api.pwnedpasswords.com/range/{head}'
        
        res = requests.get(url, timeout=5)
        if res.status_code != 200:
            return False, 0
            
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == tail:
                return True, int(count)
        return False, 0
    except requests.RequestException:
        return False, 0

def calculate_entropy(password):
    """Calculates Shannon entropy."""
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in string.punctuation for c in password): pool += len(string.punctuation)
    
    if pool == 0: return 0
    return len(password) * math.log2(pool)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({
            "score": 0, "level": "Empty", "entropy": 0,
            "breached": False, "breach_count": 0, "suggestions": []
        })

    breached, count = check_pwned_api(password)
    entropy = calculate_entropy(password)

    score = 0
    suggestions = []
    
    if len(password) < 8:
        suggestions.append("Increase password length to at least 12 characters.")
    elif len(password) < 12:
        suggestions.append("Consider making the password even longer (12+ chars) for better security.")
        score += 15
    else:
        score += 25

    if not any(c.islower() for c in password): suggestions.append("Add lowercase letters.")
    else: score += 15
    
    if not any(c.isupper() for c in password): suggestions.append("Add uppercase letters.")
    else: score += 15
    
    if not any(c.isdigit() for c in password): suggestions.append("Add numbers.")
    else: score += 15
    
    if not any(c in string.punctuation for c in password): suggestions.append("Add special characters (e.g., !@#$%).")
    else: score += 15

    if entropy > 80: score += 15
    elif entropy > 50: score += 5

    if breached:
        score = min(score, 20)
        suggestions.insert(0, f"DANGER: Password found in {count} data breaches! Do not use this.")

    score = max(0, min(100, score))

    if score < 40: level = "Weak"
    elif score < 75: level = "Moderate"
    else: level = "Strong"

    return jsonify({
        "score": score,
        "level": level,
        "entropy": round(entropy, 2),
        "breached": breached,
        "breach_count": count,
        "suggestions": suggestions
    })

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json or {}
    length = int(data.get('length', 16))
    use_upper = data.get('uppercase', True)
    use_lower = data.get('lowercase', True)
    use_numbers = data.get('numbers', True)
    use_symbols = data.get('symbols', True)

    length = max(8, min(128, length))

    if not any([use_upper, use_lower, use_numbers, use_symbols]):
        return jsonify({"error": "Select at least one character type"}), 400

    pool = ''
    req_chars = []
    
    if use_lower:
        pool += string.ascii_lowercase
        req_chars.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        pool += string.ascii_uppercase
        req_chars.append(secrets.choice(string.ascii_uppercase))
    if use_numbers:
        pool += string.digits
        req_chars.append(secrets.choice(string.digits))
    if use_symbols:
        pool += string.punctuation
        req_chars.append(secrets.choice(string.punctuation))

    remaining_length = length - len(req_chars)
    
    if remaining_length < 0:
        req_chars = req_chars[:length]
        password_chars = req_chars
    else:
        password_chars = req_chars + [secrets.choice(pool) for _ in range(remaining_length)]
        
    rng = random.SystemRandom()
    rng.shuffle(password_chars)
    
    password = ''.join(password_chars)
    return jsonify({"password": password})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)