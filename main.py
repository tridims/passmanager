from secrets import choice
from cryptography.fernet import Fernet


class PasswordManager:
    def __init__(self) -> None:
        self.key = None
        self.password_file = None
        self.password_dict = {}

    def generate_key(self, path):
        self.key = Fernet.generate_key()
        with open(path, 'wb') as key_file:
            key_file.write(self.key)
        return self.key

    def load_key(self, path):
        with open(path, 'rb') as key_file:
            self.key = key_file.read()
        return self.key

    def create_password_file(self, path, initial_values=None):
        self.password_file = path
        if initial_values is not None:
            for key, value in initial_values.items():
                self.add_password(key, value)

    def load_password_file(self, path):
        self.password_file = path
        with open(path, 'r') as password_file:
            for line in password_file:
                site, encrypted_password = line.split(':')
                self.password_dict[site] = Fernet(self.key).decrypt(
                    encrypted_password.encode()).decode()

    def add_password(self, site, password):
        self.password_dict[site] = password

        if self.password_file is not None:
            with open(self.password_file, 'a+') as password_file:
                password_file.write(
                    f'{site}:{Fernet(self.key).encrypt(password.encode()).decode()}\n')

    def get_password(self, site):
        return self.password_dict[site]


def main():
    password = {
        'github': '12345678',
        'google': '12345678',
        'facebook': '12345678',
        'instagram': '12345678',
        'linkedin': '12345678',
    }
    pm = PasswordManager()

    print("""
  1. Generate Key
  2. Load Key
  3. Create Password File
  4. Load Password File
  5. Add Password
  6. Get Password
  7. Quit""")

    while True:
        choice = input("Enter your choice: ")
        if choice == '1':
            key_path = input("Enter the path to store the key: ")
            pm.generate_key(key_path)
        elif choice == '2':
            key_path = input("Enter the path to the key: ")
            pm.load_key(key_path)
        elif choice == '3':
            password_file_path = input(
                "Enter the path to store the password file: ")
            pm.create_password_file(password_file_path, password)
        elif choice == '4':
            password_file_path = input("Enter the path to the password file: ")
            pm.load_password_file(password_file_path)
        elif choice == '5':
            site = input("Enter the site: ")
            password = input("Enter the password: ")
            pm.add_password(site, password)
        elif choice == '6':
            site = input("Enter the site: ")
            print(pm.get_password(site))
        elif choice == '7':
            break


if __name__ == '__main__':
    main()
