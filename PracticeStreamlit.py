import streamlit as st
import string
import math
import pandas as pd

# Sample weak passwords and dictionary words (expand as needed)
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "letmein", "monkey", "iloveyou", "admin", "welcome"
}
DICTIONARY_WORDS = {
    "apple", "orange", "banana", "football", "sunshine", "flower", "computer", "secret", "dragon", "master"
}

def shannon_entropy(password):
    """Calculate Shannon entropy of a string."""
    if not password:
        return 0
    freq = {}
    for c in password:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    length = len(password)
    for c in freq:
        p = freq[c] / length
        entropy -= p * math.log2(p)
    return round(entropy * length, 2)  # Total entropy in bits

def check_variety(password):
    """Check for character variety."""
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    return has_lower, has_upper, has_digit, has_special

def check_dictionary(password):
    """Check if password is in common passwords or contains dictionary words."""
    lower_pw = password.lower()
    if lower_pw in COMMON_PASSWORDS:
        return True
    for word in DICTIONARY_WORDS:
        if word in lower_pw:
            return True
    return False

def password_score(password):
    """Calculate password strength score (0-100) and breakdown."""
    length = len(password)
    has_lower, has_upper, has_digit, has_special = check_variety(password)
    entropy = shannon_entropy(password)
    in_dictionary = check_dictionary(password)

    # Length score (max 30)
    length_score = min(length * 3, 30)

    # Variety score (max 30)
    variety_score = sum([has_lower, has_upper, has_digit, has_special]) * 7.5

    # Entropy score (max 30)
    entropy_score = min(entropy, 30)

    # Dictionary penalty
    dict_penalty = 30 if in_dictionary else 0

    # Total score
    total = length_score + variety_score + entropy_score - dict_penalty
    total = max(0, min(100, int(total)))

    breakdown = {
        "Length": (length >= 12, f"{length} characters"),
        "Lowercase": (has_lower, "Has lowercase" if has_lower else "No lowercase"),
        "Uppercase": (has_upper, "Has uppercase" if has_upper else "No uppercase"),
        "Digits": (has_digit, "Has digits" if has_digit else "No digits"),
        "Special": (has_special, "Has special chars" if has_special else "No special chars"),
        "Entropy": (entropy >= 40, f"{entropy} bits"),
        "Dictionary": (not in_dictionary, "Not a dictionary/common password" if not in_dictionary else "Dictionary/common password found"),
    }

    suggestions = []
    if length < 12:
        suggestions.append("Increase password length (at least 12 characters).")
    if not has_lower:
        suggestions.append("Add lowercase letters.")
    if not has_upper:
        suggestions.append("Add uppercase letters.")
    if not has_digit:
        suggestions.append("Add digits.")
    if not has_special:
        suggestions.append("Add special characters (e.g., !@#$%).")
    if in_dictionary:
        suggestions.append("Avoid dictionary words or common passwords.")
    if entropy < 40:
        suggestions.append("Increase randomness (avoid patterns, use more character types).")

    return total, breakdown, suggestions, entropy

def strength_label(score):
    if score < 40:
        return "Weak", "red"
    elif score < 60:
        return "Medium", "orange"
    elif score < 80:
        return "Strong", "blue"
    else:
        return "Very Strong", "green"

def show_breakdown(breakdown):
    for rule, (passed, desc) in breakdown.items():
        color = "green" if passed else "red"
        st.markdown(f"- <span style='color:{color}'>{rule}: {desc}</span>", unsafe_allow_html=True)

def analyze_password(password):
    score, breakdown, suggestions, entropy = password_score(password)
    label, color = strength_label(score)
    st.markdown(f"### Strength Meter: <span style='color:{color}'>{label}</span>", unsafe_allow_html=True)
    st.progress(score)
    st.markdown(f"**Score:** {score}/100")
    st.markdown(
        f"**Entropy:** {entropy} bits "
        f"<span title='Shannon entropy estimates the unpredictability of your password. Higher is better. (40+ bits is good)'>ℹ️</span>",
        unsafe_allow_html=True
    )
    st.markdown("#### Rule Breakdown:")
    show_breakdown(breakdown)
    if suggestions:
        st.markdown("#### Suggestions:")
        for s in suggestions:
            st.write(f"- {s}")
    else:
        st.success("Your password is very strong!")

def batch_analyze(df):
    results = []
    for pw in df['password']:
        score, breakdown, suggestions, entropy = password_score(str(pw))
        label, color = strength_label(score)
        results.append({
            "Password": pw,
            "Score": score,
            "Strength": label,
            "Entropy": entropy,
            "Suggestions": "; ".join(suggestions)
        })
    return pd.DataFrame(results)

# Streamlit UI
st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔒")
st.title("🔒 Password Strength Analyzer")

tab1, tab2 = st.tabs(["Single Password", "Batch Test (CSV)"])

with tab1:
    st.subheader("Test a Password")
    password = st.text_input("Enter your password:", type="password")
    if password:
        analyze_password(password)

with tab2:
    st.subheader("Batch Test Passwords from CSV")
    st.markdown("Upload a CSV file with a column named **password**.")
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        if 'password' not in df.columns:
            st.error("CSV must have a 'password' column.")
        else:
            results_df = batch_analyze(df)
            st.dataframe(results_df)
            st.download_button(
                "Download Results as CSV",
                results_df.to_csv(index=False),
                file_name="password_strength_results.csv",
                mime="text/csv"
            )