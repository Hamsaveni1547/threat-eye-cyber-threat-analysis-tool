# # logic/password_checker.py
# import re
# import math
# import requests
# import hashlib
# from datetime import datetime
#
#
# def check_password(password):
#     if not password:
#         return {
#             'status': 'error',
#             'message': 'Password is required',
#             'data': None
#         }
#
#     try:
#         # Basic checks
#         length = len(password)
#         has_upper = bool(re.search(r'[A-Z]', password))
#         has_lower = bool(re.search(r'[a-z]', password))
#         has_digit = bool(re.search(r'\d', password))
#         has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
#
#         # Calculate complexity score
#         complexity_score = calculate_complexity_score(password)
#
#         # Check against common password lists and patterns
#         common_patterns = check_common_patterns(password)
#
#         # Check if password has been leaked (using HIBP API)
#         pwned_count = check_pwned_passwords(password)
#
#         # Calculate entropy
#         entropy = calculate_entropy(password)
#
#         # Estimate crack time
#         crack_time = estimate_crack_time(entropy)
#
#         # Determine strength rating
#         strength = determine_strength(length, has_upper, has_lower, has_digit,
#                                       has_special, complexity_score, pwned_count)
#
#         # Generate suggestions for improvement
#         suggestions = generate_suggestions(password, length, has_upper, has_lower,
#                                            has_digit, has_special, common_patterns)
#
#         # Build the final result
#         result = {
#             'status': 'success',
#             'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#             'password_length': length,
#             'basic_checks': {
#                 'has_uppercase': has_upper,
#                 'has_lowercase': has_lower,
#                 'has_digits': has_digit,
#                 'has_special_chars': has_special
#             },
#             'analysis': {
#                 'complexity_score': complexity_score,
#                 'entropy_bits': entropy,
#                 'estimated_crack_time': crack_time,
#                 'common_patterns_found': common_patterns,
#                 'appeared_in_breaches': pwned_count > 0,
#                 'breach_count': pwned_count
#             },
#             'rating': {
#                 'strength': strength,
#                 'score_out_of_100': calculate_overall_score(length, has_upper, has_lower,
#                                                             has_digit, has_special,
#                                                             complexity_score, pwned_count)
#             },
#             'suggestions': suggestions
#         }
#
#         return result
#
#     except Exception as e:
#         return {
#             'status': 'error',
#             'message': f'Error analyzing password: {str(e)}',
#             'data': None
#         }
#
#
# def calculate_complexity_score(password):
#     """Calculate a complexity score based on character variety and distribution"""
#
#     # Character set size
#     char_set_size = 0
#     if re.search(r'[a-z]', password): char_set_size += 26
#     if re.search(r'[A-Z]', password): char_set_size += 26
#     if re.search(r'\d', password): char_set_size += 10
#     if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): char_set_size += 32
#
#     # Check for good distribution of characters
#     char_counts = {}
#     for char in password:
#         char_counts[char] = char_counts.get(char, 0) + 1
#
#     unique_char_ratio = len(char_counts) / len(password)
#
#     # Calculate base score from length and character set
#     base_score = min(80, (len(password) * char_set_size) / 8)
#
#     # Adjust for character distribution
#     distribution_factor = 0.2 + (0.8 * unique_char_ratio)
#
#     return round(base_score * distribution_factor, 2)
#
#
# def check_common_patterns(password):
#     """Check for common password patterns"""
#
#     patterns_found = []
#
#     # Check for sequential numbers
#     if re.search(r'(?:0123|1234|2345|3456|4567|5678|6789|7890)', password):
#         patterns_found.append("Sequential numbers")
#
#     # Check for sequential letters
#     if re.search(
#             r'(?:abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)',
#             password.lower()):
#         patterns_found.append("Sequential letters")
#
#     # Check for keyboard patterns
#     keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456']
#     for pattern in keyboard_patterns:
#         if pattern in password.lower():
#             patterns_found.append("Keyboard pattern")
#             break
#
#     # Check for repeating characters
#     if re.search(r'(.)\1{2,}', password):
#         patterns_found.append("Repeating characters")
#
#     # Check for date patterns
#     if re.search(r'(19|20)\d{2}', password):
#         patterns_found.append("Year")
#
#     if re.search(r'(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])', password):
#         patterns_found.append("Date pattern")
#
#     return patterns_found
#
#
# def check_pwned_passwords(password):
#     """Check if password appears in data breaches using HIBP API (k-anonymity method)"""
#
#     try:
#         # Create SHA-1 hash of password
#         password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
#
#         # Get the first 5 characters (prefix)
#         prefix = password_hash[:5]
#         suffix = password_hash[5:]
#
#         # Query the API
#         response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=10)
#
#         if response.status_code != 200:
#             return 0
#
#         # Parse the response to find our hash suffix
#         hashes = response.text.splitlines()
#         for h in hashes:
#             hash_suffix, count = h.split(':')
#             if hash_suffix == suffix:
#                 return int(count)
#
#         return 0
#
#     except Exception:
#         # If API call fails, return 0 to be safe
#         return 0
#
#
# def calculate_entropy(password):
#     """Calculate password entropy in bits"""
#
#     char_set_size = 0
#     if re.search(r'[a-z]', password): char_set_size += 26
#     if re.search(r'[A-Z]', password): char_set_size += 26
#     if re.search(r'\d', password): char_set_size += 10
#     if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): char_set_size += 32
#
#     # Shannon entropy formula
#     entropy = len(password) * math.log2(max(char_set_size, 1))
#
#     return round(entropy, 2)
#
#
# def estimate_crack_time(entropy):
#     """Estimate the time needed to crack a password based on its entropy"""
#
#     # Assuming 10 billion guesses per second (modern attacker)
#     guesses_per_second = 10_000_000_000
#
#     # Calculate number of possible combinations
#     possible_combinations = 2 ** entropy
#
#     # Calculate seconds needed
#     seconds = possible_combinations / guesses_per_second
#
#     # Convert to human-readable format
#     if seconds < 60:
#         return "Instant"
#     elif seconds < 3600:
#         return f"{round(seconds / 60)} minutes"
#     elif seconds < 86400:
#         return f"{round(seconds / 3600)} hours"
#     elif seconds < 31536000:
#         return f"{round(seconds / 86400)} days"
#     elif seconds < 315360000:
#         return f"{round(seconds / 31536000)} years"
#     else:
#         centuries = seconds / 31536000 / 100
#         return f"{round(centuries)} centuries"
#
#
# def determine_strength(length, has_upper, has_lower, has_digit, has_special, complexity_score, pwned_count):
#     """Determine password strength category"""
#
#     if pwned_count > 0:
#         return "Very Weak (Compromised)"
#
#     if length < 8:
#         return "Very Weak"
#
#     if complexity_score < 40:
#         return "Weak"
#
#     if length >= 12 and has_upper and has_lower and has_digit and has_special and complexity_score >= 70:
#         return "Very Strong"
#
#     if length >= 10 and has_upper and has_lower and has_digit and complexity_score >= 60:
#         return "Strong"
#
#     return "Moderate"
#
#
# def calculate_overall_score(length, has_upper, has_lower, has_digit, has_special, complexity_score, pwned_count):
#     """Calculate overall score out of 100"""
#
#     # Start with complexity score
#     score = complexity_score
#
#     # Penalize for pwned passwords
#     if pwned_count > 0:
#         penalty = min(50, pwned_count)
#         score = max(0, score - penalty)
#
#     # Ensure at least basic requirements are met
#     if length < 8 or not (has_upper and has_lower and has_digit):
#         score = min(score, 60)
#
#     # Reward for extra length
#     if length > 12:
#         score = min(100, score + (length - 12) * 2)
#
#     return round(score)
#
#
# def generate_suggestions(password, length, has_upper, has_lower, has_digit, has_special, common_patterns):
#     """Generate suggestions to improve the password"""
#
#     suggestions = []
#
#     if length < 12:
#         suggestions.append("Increase password length to at least 12 characters")
#
#     if not has_upper:
#         suggestions.append("Add uppercase letters")
#
#     if not has_lower:
#         suggestions.append("Add lowercase letters")
#
#     if not has_digit:
#         suggestions.append("Add numbers")
#
#     if not has_special:
#         suggestions.append("Add special characters")
#
#     if common_patterns:
#         suggestions.append("Avoid common patterns: " + ", ".join(common_patterns))
#
#     if not suggestions:
#         suggestions.append("Your password meets all basic security requirements")
#
#     return suggestions


import re
from datetime import datetime
import math


def check_password(password):
    """
    Check the strength of a password

    Args:
        password (str): The password to check

    Returns:
        dict: Analysis results
    """
    result = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'length': len(password),
        'strength_score': 0,
        'has_lowercase': bool(re.search(r'[a-z]', password)),
        'has_uppercase': bool(re.search(r'[A-Z]', password)),
        'has_numbers': bool(re.search(r'[0-9]', password)),
        'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
        'weaknesses': [],
        'repeated_characters': check_repeated_characters(password),
        'sequential_characters': check_sequential_characters(password),
        'common_patterns': check_common_patterns(password),
        'entropy': calculate_entropy(password)
    }

    # Check length
    if result['length'] < 8:
        result['weaknesses'].append('Password is too short (minimum 8 characters recommended)')
    elif result['length'] < 12:
        result['weaknesses'].append('Password could be longer (12+ characters is recommended)')

    # Check character types
    if not result['has_lowercase']:
        result['weaknesses'].append('No lowercase letters')
    if not result['has_uppercase']:
        result['weaknesses'].append('No uppercase letters')
    if not result['has_numbers']:
        result['weaknesses'].append('No numbers')
    if not result['has_special']:
        result['weaknesses'].append('No special characters')

    # Calculate base score
    score = 0

    # Length contributes up to 40 points
    length_score = min(40, result['length'] * 4)
    score += length_score

    # Character variety contributes up to 40 points
    char_variety_score = 0
    if result['has_lowercase']: char_variety_score += 10
    if result['has_uppercase']: char_variety_score += 10
    if result['has_numbers']: char_variety_score += 10
    if result['has_special']: char_variety_score += 10
    score += char_variety_score

    # Deduct points for weaknesses (up to 40 points)
    weakness_penalty = 0

    # Repeated characters reduce score
    if result['repeated_characters']['has_repeats']:
        repeat_penalty = min(20, result['repeated_characters']['count'] * 5)
        weakness_penalty += repeat_penalty
        result['weaknesses'].append(f"Contains {result['repeated_characters']['count']} repeated character patterns")

    # Sequential characters reduce score
    if result['sequential_characters']['has_sequences']:
        seq_penalty = min(20, result['sequential_characters']['count'] * 5)
        weakness_penalty += seq_penalty
        result['weaknesses'].append(
            f"Contains {result['sequential_characters']['count']} sequential character patterns")

    # Common patterns reduce score
    if result['common_patterns']['has_patterns']:
        pattern_penalty = min(20, len(result['common_patterns']['patterns']) * 10)
        weakness_penalty += pattern_penalty
        for pattern in result['common_patterns']['patterns']:
            result['weaknesses'].append(f"Contains common pattern: {pattern}")

    # Apply penalty
    score = max(0, score - weakness_penalty)

    # Additional bonus for high entropy
    if result['entropy'] > 60:
        entropy_bonus = min(20, (result['entropy'] - 60) / 2)
        score = min(100, score + entropy_bonus)

    result['strength_score'] = round(score, 1)

    # Password strength category
    if score >= 80:
        result['strength'] = 'Very Strong'
        result['recommendations'] = [
            "Excellent password strength.",
            "Remember to use unique passwords for different accounts.",
            "Consider using a password manager to store this complex password."
        ]
    elif score >= 60:
        result['strength'] = 'Strong'
        result['recommendations'] = [
            "Good password strength.",
            "For even better security, consider increasing length or complexity.",
            "Using a password manager is recommended."
        ]
    elif score >= 40:
        result['strength'] = 'Medium'
        result['recommendations'] = [
            "Moderate password strength.",
            "Add more character types or increase length.",
            "Avoid using recognizable patterns or words."
        ]
    elif score >= 20:
        result['strength'] = 'Weak'
        result['recommendations'] = [
            "This password needs improvement.",
            "Add uppercase letters, numbers, and special characters.",
            "Increase the length to at least 12 characters."
        ]
    else:
        result['strength'] = 'Very Weak'
        result['recommendations'] = [
            "This password is highly vulnerable to brute force attacks.",
            "Create a completely new password with a mix of characters.",
            "Use a password generator for better security."
        ]

    return result


def check_repeated_characters(password):
    """
    Check for repeated character patterns in the password
    """
    result = {'has_repeats': False, 'count': 0, 'patterns': []}

    # Check for any character repeated 3 or more times (e.g., 'aaa')
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            result['has_repeats'] = True
            result['count'] += 1
            result['patterns'].append(password[i:i + 3])

    # Check for repeated pairs (e.g., 'abcabc')
    for length in range(2, len(password) // 2 + 1):
        for i in range(len(password) - length * 2 + 1):
            if password[i:i + length] == password[i + length:i + length * 2]:
                result['has_repeats'] = True
                result['count'] += 1
                result['patterns'].append(password[i:i + length * 2])

    return result


def check_sequential_characters(password):
    """
    Check for sequential character patterns in the password
    """
    result = {'has_sequences': False, 'count': 0, 'sequences': []}

    # Common sequences to check against
    sequences = [
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm'
    ]

    password_lower = password.lower()

    for seq in sequences:
        for i in range(len(seq) - 2):
            pattern = seq[i:i + 3]
            if pattern in password_lower:
                result['has_sequences'] = True
                result['count'] += 1
                result['sequences'].append(pattern)

            # Check for reverse sequences too
            rev_pattern = pattern[::-1]
            if rev_pattern in password_lower:
                result['has_sequences'] = True
                result['count'] += 1
                result['sequences'].append(rev_pattern)

    return result


def check_common_patterns(password):
    """
    Check for common password patterns
    """
    result = {'has_patterns': False, 'patterns': []}
    password_lower = password.lower()

    # Check for common substitutions
    substitutions = {
        '0': 'o',
        '1': 'i',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '8': 'b',
        '@': 'a',
        '$': 's'
    }

    normalized_pwd = password_lower
    for num, letter in substitutions.items():
        normalized_pwd = normalized_pwd.replace(num, letter)

    # Common words and patterns to check
    common_patterns = [
        'password', 'pass', 'admin', 'welcome', 'qwerty',
        '123', 'abc', '111', '000', 'letmein',
        'monkey', 'dragon', 'football', 'baseball', 'superman',
        'login', 'master', 'sunshine', 'shadow', 'qazwsx'
    ]

    for pattern in common_patterns:
        if pattern in normalized_pwd:
            result['has_patterns'] = True
            result['patterns'].append(pattern)

    # Check for years
    year_pattern = r'19\d{2}|20\d{2}'
    years = re.findall(year_pattern, password)
    if years:
        result['has_patterns'] = True
        for year in years:
            result['patterns'].append(f'year ({year})')

    # Check for dates
    date_patterns = [
        r'\d{1,2}\/\d{1,2}\/\d{2,4}',  # MM/DD/YYYY
        r'\d{1,2}\-\d{1,2}\-\d{2,4}',  # MM-DD-YYYY
        r'\d{1,2}\.\d{1,2}\.\d{2,4}'  # MM.DD.YYYY
    ]

    for pattern in date_patterns:
        dates = re.findall(pattern, password)
        if dates:
            result['has_patterns'] = True
            for date in dates:
                result['patterns'].append(f'date ({date})')

    return result


def calculate_entropy(password):
    """
    Calculate the entropy (randomness) of a password
    Higher entropy means more randomness and better security
    """
    # Calculate character set size
    char_sets = {
        'lowercase': len(re.findall(r'[a-z]', password)),
        'uppercase': len(re.findall(r'[A-Z]', password)),
        'numbers': len(re.findall(r'[0-9]', password)),
        'special': len(re.findall(r'[^a-zA-Z0-9]', password))
    }

    # Calculate pool size
    pool_size = 0
    if char_sets['lowercase'] > 0: pool_size += 26  # a-z
    if char_sets['uppercase'] > 0: pool_size += 26  # A-Z
    if char_sets['numbers'] > 0: pool_size += 10  # 0-9
    if char_sets['special'] > 0: pool_size += 33  # Special characters

    # Calculate entropy using formula: log2(pool_size^length)
    if pool_size > 0:
        entropy = math.log2(pool_size) * len(password)
    else:
        entropy = 0

    return round(entropy, 2)