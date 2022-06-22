import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class PasswordManager:

    def __init__(self) -> None:
        self.password_dir = os.path.expanduser('~') + '/.password_manager'
        self.initialized = os.path.exists(self.password_dir)

    def init_app(self):
        if not self.initialized:
            os.makedirs(self.password_dir)
            self.salt = os.urandom(16)
            with open(self.password_dir + '/salt', 'wb') as salt_file:
                salt_file.write(self.salt)

            return True
        else:
            return False

    def generate_key(self, main_password: str, method='scrypt'):
        with open(self.password_dir + '/salt', 'rb') as salt_file:
            self.salt = salt_file.read()
        if method == 'pbkdf2hmac':
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=390000,
            )
        elif method == 'scrypt':
            kdf = Scrypt(
                salt=self.salt,
                length=32,
                n=2**20,
                r=8,
                p=1,
            )

        key = base64.urlsafe_b64encode(kdf.derive(main_password.encode()))
        return key

    def encrypt_password(self, password, key):
        encrypted_password = Fernet(key).encrypt(password.encode())
        return encrypted_password

    def add_password(self, siteName: str, username: str, site_password: str, main_password: str):
        if not self.initialized:
            return False
        try:
            folder = self.password_dir + '/' + siteName
            if not os.path.exists(folder):
                os.makedirs(folder)
            encrypted_password = self.encrypt_password(
                site_password, self.generate_key(main_password))
            with open(folder + '/' + username + '.pass', 'wb') as password_file:
                password_file.write(encrypted_password)
            return True
        except:
            return False

    def delete_password(self, siteName, username, main_password):
        if not self.initialized:
            raise Exception('Password manager not initialized')
        try:
            folder = self.password_dir + '/' + siteName
            password_file_path = folder + '/' + username + '.pass'
            key = self.generate_key(main_password)
            with open(password_file_path, 'rb') as password_file:
                encrypted_password = password_file.read()

            # try to decrypt the password
            _ = Fernet(key).decrypt(encrypted_password)

            # if decrypted, delete the file
            os.remove(password_file_path)
            return True
        except:
            return False

    def get_list_password_file_path(self):
        if not self.initialized:
            raise Exception('Password manager not initialized')
        list_password_file_path = []
        for root, dirs, files in os.walk(self.password_dir):
            for file in files:
                if file.endswith('.pass'):
                    list_password_file_path.append(os.path.join(root, file))
        return list_password_file_path

    def get_password(self, site: str, username: str, main_password: str):
        password_file_path = self.password_dir + '/' + site + '/' + username + '.pass'
        if not self.initialized:
            raise Exception('Password manager not initialized')
        try:
            key = self.generate_key(main_password)
            with open(password_file_path, 'rb') as password_file:
                encrypted_password = password_file.read()
            decrypted_password = Fernet(key).decrypt(encrypted_password)
            return decrypted_password.decode()
        except Exception as e:
            print(e)
            return False
