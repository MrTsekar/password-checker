from flask import Flask, render_template, request
import re

app = Flask(__name__)

def load_common_weak_passwords(file_path):
    with open(file_path) as f:
        return {line.strip() for line in f}

COMMON_WEAK_PASSWORDS = load_common_weak_passwords('fasttrack.txt')

def check_password_strength(password):
    checks = [
        (len(password) >= 8, "Password must be at least 8 characters long."),
        (re.search(r"[A-Z]", password), "Password must contain at least one uppercase letter."),
        (re.search(r"[a-z]", password), "Password must contain at least one lowercase letter."),
        (re.search(r"[0-9]", password), "Password must contain at least one digit."),
        (re.search(r"[!@#$%^&*(),.?\":{}|<>]", password), "Password must contain at least one special character."),
        (password not in COMMON_WEAK_PASSWORDS, "Password found in a data breach.")
    ]
    
    messages = [msg for valid, msg in checks if not valid]
    return len(messages) == 0, messages  

def analyze_policy(policy):
    recommendations = [
        ("Increase minimum password length to at least 8 characters." if policy.get('min_length', 0) < 8 else None),
        ("Require at least one uppercase letter." if not policy.get('require_uppercase', False) else None),
        ("Require at least one lowercase letter." if not policy.get('require_lowercase', False) else None),
        ("Require at least one digit." if not policy.get('require_digits', False) else None),
        ("Require at least one special character." if not policy.get('require_special_chars', False) else None)
    ]
    
    return [rec for rec in recommendations if rec]

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user_password = request.form['password']
        
        is_strong, messages = check_password_strength(user_password)

        sample_policy = {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_special_chars': True  
        }
        
        recommendations = analyze_policy(sample_policy)
        
        if is_strong:
            recommendations.append("Change every 3 months.")

        return render_template('results.html', 
                               is_strong=is_strong,
                               message=messages,
                               recommendations=recommendations)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
