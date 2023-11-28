import requests
import hashlib
import re
import sys

#01a03696094643ea261a7f367b5f204b57132a64

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error getting response: {res.status_code}')
    return res

def pwned_api_check(x,tail):
    # temp  = x.content
    # responses = list(temp.decode('utf-8').split('\n'))
    # for response in responses:
    #     if re.findall(tail,response):
    #         response_text, count = response.
    #         print(f'{response_text} match found in {count}s')
    #         return None
    #     else:
    #         continue
    # print('No Match found')
    responses = (line.split(':') for line in x.text.splitlines())
    for response, count in responses:
        if response == tail:
            return count
        else:
            continue
    return False

def hash_password(password):
    hashed_password = hashlib.sha1(password.encode('utf-8'))
    query_char = hashed_password.hexdigest()[0:5].upper()
    tail = hashed_password.hexdigest()[5:].upper()
    return query_char, tail


def main(args):
    for arg in args:
        input_password = arg
        query_char, tail = hash_password(input_password)
        res = request_api_data(query_char)
        count = pwned_api_check(res, tail)
        if count:
            print(f'For password {arg} match found for {count} instances')
        else:
            print(f'No Match found for password {arg}')


main(sys.argv[1:])

