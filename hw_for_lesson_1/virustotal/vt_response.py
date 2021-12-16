import json
import requests
import os
import sys

files_list = []


def shaping_files_list(path_to_file):
    global files_list
    if not os.path.exists('files_list.json') or os.stat('files_list.json').st_size == 0:
        print('Please run vt_request.py first.')
        sys.exit()
    with open(path_to_file, 'r') as files_list_file:
        for element in json.load(files_list_file):
            files_list.append(element)


def print_data_about_files_to_log_file():
    global files_list
    with open('files_list.json', 'w', encoding='UTF-8') as files_list_file:
        print(json.dumps(files_list, sort_keys=False, indent=4), file=files_list_file)


def vt_response():
    shaping_files_list('files_list.json')
    with open('logs_vt_response.json', 'w') as logs_vt_response:
        print('', file=logs_vt_response)
    result = []
    for element in files_list:
        if element['clean'] == 'in queue':
            api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = dict(apikey='7ef03dba070f2324da28a6d7c210e01ca5f1c3dc1ced438a62db9b78fef384a0',
                          resource=element['scan_id'])
            response = requests.get(api_url, params=params)
            if response.status_code == 200:
                req = response.json()
                if req['response_code'] == 1:
                    if req['positives'] != 0:
                        element['clean'] = 'no'
                        print(f'Spy program detected in {element["filename"]}. More information in '
                              f'logs_vt_response.json.')
                    else:
                        element['clean'] = 'yes'
                        print(f'File {element["filename"]} clean.')
                else:
                    print(f'File {element["filename"]} has not been verified yet. More information in '
                          f'logs_vt_response.json.')
            result.append(req)

        else:
            print(f'File {element["filename"]} already scanned.')
    with open('logs_vt_response.json', 'a') as logs_vt_response:
        print(json.dumps(result, sort_keys=False, indent=4), file=logs_vt_response)
    print_data_about_files_to_log_file()


vt_response()
