import re

def assess_password_strength(password):
    length = len(password)

    if length < 8:
        return "Weak", ["Password is too short (less than 8 characters)."]

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^\w]", password))  # non-alphanumeric

    if has_upper and has_lower and has_special:
        return "Strong", ["Good mix of uppercase, lowercase, and special characters."]
    elif (has_upper or has_lower) and has_digit:
        return "Moderate", ["Includes letters and numbers."]
    else:
        return "Weak", ["Password lacks required variety (letters, numbers, symbols)."]

def main():
    print("=" * 40)
    print("🛡️ Password Strength Checker")
    print("=" * 40)

    while True:
        password = input("\nEnter your password: ").strip()
        if not password:
            print("⚠️  No input provided. Please try again.")
            continue

        strength, feedback = assess_password_strength(password)
        
        print(f"\n🔍 Password Strength: {strength}")
        print("📋 Feedback:")
        for line in feedback:
            print(" -", line)

        retry = input("\n🔁 Try another password? (y/n): ").lower()
        if retry != 'y':
            print("✅ Exiting. Stay safe!")
            break

if __name__ == "__main__":
    main()
