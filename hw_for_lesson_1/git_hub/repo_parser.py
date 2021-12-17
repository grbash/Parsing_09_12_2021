import requests
import json
import sys

user = input('Enter username: ')  # Для тестов использовал свой профиль 'grbash'

url = f'https://api.github.com/users/{user}/repos'  # (не разобрался в чем разница между org и users)

headers = {'Accept': 'application/vnd.github.v3+json'}

req = requests.get(url, headers=headers)
if req.ok:
    data = json.loads(req.text)
else:
    print(f'Response code {req.status_code}')
    sys.exit()
with open('repos_list.json', 'w', encoding="UTF-8") as file:
    print(data, file=file)

repos_names = []
for element in data:
    repos_names.append(element['name'])

output_str = f'User {user} have {len(repos_names)}: '
for i in range(len(repos_names)):
    if i == len(repos_names) - 1:
        output_str += f'{repos_names[i]}.'
    else:
        output_str += f'{repos_names[i]}, '

print(output_str)
