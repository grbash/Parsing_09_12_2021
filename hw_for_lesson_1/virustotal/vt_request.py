import hashlib
import json
import requests
import os
from pathlib import Path

tests_dir = Path(os.path.abspath(os.curdir), 'files')
files = os.listdir(tests_dir)
files_list = []


def shaping_current_files_list():
    global files_list
    if not os.path.exists('files_list.json') or os.stat('files_list.json').st_size == 0:
        with open('files_list.json', 'w') as files_list_file:
            print(json.dumps(files_list, sort_keys=False, indent=4), file=files_list_file)
            print('File files_list.json created successfully.')
    with open('files_list.json', 'r') as files_list_file:
        for element in json.load(files_list_file):
            files_list.append(element)


def sha256_of_file(path_to_file):
    with open(path_to_file, "rb") as f:
        bytes = f.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()
    return readable_hash


def writing_data_about_new_files(filename, hash, scan_id):
    global files_list
    files_list.append({'filename': filename, 'hash': hash, 'scan_id': scan_id, 'clean': 'in queue'})


def print_data_about_files_to_log_file():
    global files_list
    with open('files_list.json', 'w', encoding='UTF-8') as files_list_file:
        print(json.dumps(files_list, sort_keys=False, indent=4), file=files_list_file)


def send_to_vt():
    shaping_current_files_list()
    api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = dict(apikey='7ef03dba070f2324da28a6d7c210e01ca5f1c3dc1ced438a62db9b78fef384a0')
    global tests_dir
    global files
    global files_list
    current_hash_list = []
    result = []
    with open('logs_vt_request.json', 'a') as logs_send_to_vt_file:
        print('', file=logs_send_to_vt_file)
    for element in files_list:
        current_hash_list.append(element['hash'])
    i = 0
    for current_filename in files:
        if sha256_of_file(Path(tests_dir, current_filename)) not in current_hash_list:
            i = 1
            with open(Path(tests_dir, current_filename), 'rb') as file:
                files_to_vt = dict(file=(current_filename, file))
                response = requests.post(api_url, files=files_to_vt, params=params)
            if response.status_code == 200:
                req = response.json()
                writing_data_about_new_files(current_filename, req['sha256'], req['scan_id'])
                result.append(req)
                if req['response_code'] == 1:
                    print(current_filename)
                    print('File sent successfully.')
                else:
                    print(current_filename)
                    print('File sent unsuccessfully. Check logs_send_to_vt.txt for more information.')
    if i == 0:
        print('Files have not changed')
    with open('logs_vt_request.json', 'a') as logs_send_to_vt_file:
        print(json.dumps(result, sort_keys=False, indent=4), file=logs_send_to_vt_file)
    print_data_about_files_to_log_file()


send_to_vt()
