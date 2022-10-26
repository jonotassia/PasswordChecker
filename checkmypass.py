import requests
import hashlib
import sys


def request_api_data(query_char):
    # passing only the first 5 chars of the hash will not narrow down our password completely
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if hash_to_check == h:
            return count


def pwned_api_check(password):
    '''Checks that password exists in database'''
    sha1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_pass[:5], sha1_pass[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for pw in args:
        print(pwned_api_check(pw))


if __name__ == '__main__':
    exit(main(sys.argv[1:]))