import imapclient
import getpass
import pyzmail
import json
import os
import hashlib
import base64
import colorama


class Client_User:

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def register(self):
        user_data = {}
        user_data['user_info'] = []

        user_data['user_info'].append({
            'username': self.username,
            'email': self.email,
            'password': password_manager(self.password).hash_func()
        })
        JSON_data().write_json(user_data)

    def login(self):
        client = Client_Connection(self.email, self.password).make_connection()
        client.select_folder('INBOX', readonly=True)        
        Read_Emails(client).read()


class Read_Emails:

    def __init__(self, main_client):
        self.main_client = main_client

    def read(self):
        UIDs = self.main_client.search(['ALL'])[-30:]
        print(f"You have {'{:,}'.format(len(self.main_client.search(['ALL'])))} emails in your inbox.")
        if UIDs[-1] == 0:
            UIDs = UIDs[:-1]

        print(colorama.Fore.YELLOW, f"Getting {len(UIDs)} recent emails...", colorama.Style.RESET_ALL)
        rawMessage = self.main_client.fetch(UIDs, ['BODY[]', 'FLAGS'])
        for index, i in enumerate(rawMessage, start=1):
            message = pyzmail.PyzMessage.factory(rawMessage[i][b'BODY[]'])
            print(f"#{index} - {message.get_subject()} from: {message.get_addresses('from')[0][0]}\n")


class Client_Connection:

    def __init__(self, client_email, client_password):
        self.client_email = client_email
        self.client_password = client_password

    def make_connection(self):
        try:
            conn = imapclient.IMAPClient('imap.gmail.com', ssl=True)
            conn.login(self.client_email, self.client_password)

            return conn
        except imapclient.exceptions.LoginError as logerr:
            print(colorama.Fore.RED,
                f'[!!] Something wrong just happened! {logerr}', colorama.Style.RESET_ALL)


class password_manager:

    def __init__(self, password):
        self.password = password

    def hash_func(self):
        salt = base64.b64encode(os.urandom(64)).decode('utf-8')
        key = base64.b64encode(hashlib.pbkdf2_hmac('sha256', self.password.encode(), base64.b64decode(salt.encode('utf-8')), 100000)).decode('utf-8')
        return salt+key

    def verify_pass(self):
        source = JSON_data().read_json()
        for x in source['user_info']:
            new_key = hashlib.pbkdf2_hmac('sha256', self.password.encode('utf-8'), base64.b64decode(x['password'][:88].encode('utf-8')), 100000)
            if new_key == base64.b64decode(x['password'][88:].encode('utf-8')):
                print(colorama.Fore.GREEN,
                    f"[*] Authentication Successful! Welcome, {x['username']}", colorama.Style.RESET_ALL)
                return self.password


class JSON_data:

    def write_json(self, data, filename='user.json'):
        with open(filename, 'w', encoding='utf-8') as f_source:
            json.dump(data, f_source, indent=2)

    def read_json(self, filename='user.json'):
        with open(filename, 'r', encoding='utf-8') as j_source:
            source = json.load(j_source)
            return source


def prompt_user():
    name = str(input('Enter name: '))
    email = str(input('Enter email: '))
    passwd = getpass.getpass('Enter Password: ')
    conf_passwd = getpass.getpass('Re-Enter Password: ')
    if not passwd == conf_passwd:
        print(colorama.Fore.RED, '[!!] Passwords do not match!',
            colorama.Style.RESET_ALL)
    else:
        Client_User(name, email, passwd).register()


if __name__ == '__main__':
    colorama.init()
    if not os.path.exists('user.json'):
        prompt_user()
    else:
        passwd = getpass.getpass('Enter Password: ')
        source = JSON_data().read_json()
        try:
            for creds in source['user_info']:
                Client_User(creds['username'], creds['email'], password_manager(passwd).verify_pass()).login()
        except SystemError as err:
            print(colorama.Fore.RED,
                f'[!!] Something went wrong! {err}', colorama.Style.RESET_ALL)