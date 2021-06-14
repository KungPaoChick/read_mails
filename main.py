from getpass import getpass
from pyzmail import PyzMessage
from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac
from argparse import RawDescriptionHelpFormatter, ArgumentParser
import imapclient
import json
import os
import colorama


class Client_User:

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def register(self):
        user_data = {
            'uid_limit': 5,
            'user_info': []
        }
        user_data['user_info'].append({
            'username': self.username,
            'email': self.email,
            'password': Password_Manager(self.password).hash_func()
        })
        JSON_data().write_json(user_data)

    def login(self):
        client = Client_Connection(self.email, self.password).make_connection()
        client.select_folder('INBOX', readonly=True)
        Emails(client).read()


class Emails:

    def __init__(self, main_client):
        self.main_client = main_client

    def read(self):
        limit_UID = JSON_data().read_json()
        UIDs = self.main_client.search(['ALL'])[-limit_UID['uid_limit']:]
        print(f"You have {'{:,}'.format(len(self.main_client.search(['ALL'])))} emails in your inbox.")
        if UIDs[-1] == 0:
            UIDs = UIDs[:-1]

        print(colorama.Fore.YELLOW, f"[!] Getting {'{:,}'.format(len(UIDs))} recent emails...", colorama.Style.RESET_ALL)
        rawMessage = self.main_client.fetch(UIDs, ['BODY[]', 'FLAGS'])
        for index, i in enumerate(rawMessage, start=1):
            try:
                message = PyzMessage.factory(rawMessage[i][b'BODY[]'])
                print(colorama.Fore.GREEN, f'\n\n\n#{index}', colorama.Style.RESET_ALL,
                    f" - {message.get_subject()} from: {message.get_addresses('from')[0][0]}\n")
                print(message.text_part.get_payload().decode('utf-8'))
            except (AttributeError, UnicodeDecodeError):
                continue


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


class Password_Manager:

    def __init__(self, password):
        self.password = password

    def hash_func(self):
        salt = b64encode(os.urandom(64)).decode('utf-8')
        key = b64encode(pbkdf2_hmac('sha256', self.password.encode(), b64decode(salt.encode('utf-8')), 100000)).decode('utf-8')
        return salt+key

    def verify_pass(self):
        source = JSON_data().read_json()
        for x in source['user_info']:
            new_key = pbkdf2_hmac('sha256', self.password.encode('utf-8'), b64decode(x['password'][:88].encode('utf-8')), 100000)
            if new_key == b64decode(x['password'][88:].encode('utf-8')):
                print(colorama.Fore.GREEN,
                    f"[*] Authentication Successful! Welcome, {x['username']}", colorama.Style.RESET_ALL)
                return self.password
            else:
                print(colorama.Fore.RED, f'[!!] Authentication Failed!', colorama.Style.RESET_ALL)
                quit()


class JSON_data:

    def write_json(self, data, filename='user.json'):
        with open(filename, 'w', encoding='utf-8') as f_source:
            json.dump(data, f_source, indent=2)

    def read_json(self, filename='user.json'):
        with open(filename, 'r', encoding='utf-8') as j_source:
            source = json.load(j_source)
            return source


class Config:

    def change_uid_limit(self, num):
        source = JSON_data().read_json()

        source['uid_limit'] = num
        JSON_data().write_json(source)
        print(colorama.Fore.GREEN, f"[*] Setted UID limit to {'{:,}'.format(num)}",
                colorama.Style.RESET_ALL)

    def change_username(self, name):
        verification = getpass('Enter Password: ')
        if bool(Password_Manager(verification).verify_pass()):
            source = JSON_data().read_json()

            for content in source['user_info']:
                if content['username'] == name:
                    print(colorama.Fore.YELLOW,
                        f'[!] Username is already {name}', colorama.Style.RESET_ALL)
                else:
                    content['username'] = name
                    JSON_data().write_json(source)
                    print(colorama.Fore.GREEN,
                        f'[*] Username Successfully changed to: {name}', colorama.Style.RESET_ALL)

    def prompt_user(self):
        name = str(input('Enter name: '))
        email = str(input('Enter email: '))
        passwd = getpass('Enter Password: ')
        conf_passwd = getpass('Re-Enter Password: ')
        if not passwd == conf_passwd:
            print(colorama.Fore.RED, '[!!] Passwords do not match!',
                colorama.Style.RESET_ALL)
        else:
            Client_User(name, email, passwd).register()

    def switch_user(self):
        confirm = getpass('Enter Old Password: ')
        if bool(Password_Manager(confirm).verify_pass()):
            Config().prompt_user()

    def current_user(self):
        if os.path.exists('user.json'):
            source = JSON_data().read_json()
            for info in source['user_info']:
                print(colorama.Fore.YELLOW, f"[!] Current User: ",
                        colorama.Style.RESET_ALL, f"Username: {info['username']} - Email: {info['email']}")
        else:
            print(colorama.Fore.RED, '[!!] No user is currently registered.',
                    colorama.Style.RESET_ALL)


if __name__ == '__main__':
    colorama.init()
    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                            description='Reads Emails')

    parser.add_argument('--set_uid_limit', type=int,
                        action='store', help='Sets UID limit.')

    parser.add_argument('--set_name', type=str,
                        action='store', help='Changes username')

    parser.add_argument('--switch_user',
                        action='store_true', help='Switch User')

    parser.add_argument('--current_user',
                        action='store_true',
                        help='Views current user')

    args = parser.parse_args()
    if args.set_uid_limit:
        Config().change_uid_limit(args.set_uid_limit)
    elif args.set_name:
        Config().change_username(args.set_name)
    elif args.switch_user:
        Config().switch_user()
    elif args.current_user:
        Config().current_user()
    else:
        if not os.path.exists('user.json'):
            Config().prompt_user()
        else:
            try:
                passwd = getpass('Enter Password: ')
                source = JSON_data().read_json()
                try:
                    for creds in source['user_info']:
                        Client_User(creds['username'], creds['email'], Password_Manager(passwd).verify_pass()).login()
                except SystemError as err:
                    print(colorama.Fore.RED,
                        f'[!!] Something went wrong! {err}', colorama.Style.RESET_ALL)
            except KeyboardInterrupt:
                print('\nStopped!')
