from pwn import *
import re
import hashlib
import argparse


def valid_hash(hash_string):
    # Checks if the provided hash is a sha256sum.
    pattern = re.compile(r'^[a-fA-F0-9]{64}$')
    if pattern.match(hash_string):
        return hash_string
    else:
        raise argparse.ArgumentTypeError("Provided string is not a valid SHA-256 hash.")


def arguments():
    parser = argparse.ArgumentParser(description='SHA256sum crack by 0Pa1')
    parser.add_argument('-H', '--hash', required=True, type=valid_hash, help='Hash to crack')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to desired wordlist')
    return parser


def sha256sum(text):
    # Compute the SHA-256 hash of the given text and return the hexadecimal digest.
    return hashlib.sha256(text.encode()).hexdigest()


def crack_password(target_hash, wordlist):
    attempts = 0
    with log.progress(f'Attempting to crack : {target_hash}') as p:
        try:
            with open(wordlist, 'r') as password_list:
                for password in password_list:
                    password = password.strip()
                    password_hash = sha256sum(password)
                    p.status(f'{attempts} {password} == {password_hash}')
                    if password_hash == target_hash:
                        p.success(f'\nPassword found after {attempts} attempts: [{password}]')
                        return True
                    attempts += 1
        except FileNotFoundError:
            p.failure(f'\n[X] The file {wordlist} could not be found.')
            return False
        p.failure('\nPassword hash is not found.')
        return False


def main():
    try:
        parser = arguments()
        args = parser.parse_args()
        if not crack_password(args.hash, args.wordlist):
            print('[!] Password cracking unsuccessful.')
    except KeyboardInterrupt:
        print('\n[!] Execution interrupted by the user.')


if __name__ == '__main__':
    main()
