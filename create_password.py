import base64
import hashlib
import secrets
import string


def create():
    alphabet = string.digits + string.ascii_letters

    password = ''.join(secrets.choice(alphabet) for i in range(128))
    salt = ''.join(secrets.choice(alphabet) for i in range(64))
    hashed_and_salted_bytes = hashlib.pbkdf2_hmac(
        'sha256', password.encode('ascii'), salt.encode('ascii'), iterations=1000000)
    hashed_and_salted = base64.b64encode(hashed_and_salted_bytes).decode('ascii')

    print(f'Password:          {password}')
    print(f'Salt:              {salt}')
    print(f'Hashed and salted: {hashed_and_salted}')


create()
