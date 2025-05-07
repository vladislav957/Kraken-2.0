import hashlib
import itertools
import string

def brute_force_sha256(target_hash, max_length=4):
    chars = string.ascii_lowercase + string.digits  # Алфавит
    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            guess = ''.join(guess)
            guess_hash = hashlib.sha256(guess.encode()).hexdigest()
            if guess_hash == target_hash:
                return guess
    return None

# Пример использования
password = "10"
hashed_password = hashlib.sha256(password.encode()).hexdigest()

cracked = brute_force_sha256(hashed_password, max_length=3)
print(f"Найденный пароль: {cracked}")
