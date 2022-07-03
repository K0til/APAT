import json
import re
import requests
import os
from bs4 import BeautifulSoup as Soup

class UpdateData:
    def __init__(self):
        response = requests.get('https://developer.android.com/reference/android/Manifest.permission')
        content = Soup(response.content, 'html.parser')
        online_permissions = {}
        permissions = content.find_all('div', {'data-version-added': re.compile(r'\d*')})
        for i in permissions:
            permission_name = i.find('h3').contents[0]
            if permission_name in ['Constants', 'Manifest.permission']:
                continue
            try:
                protection_level = re.search(r'Protection level\: (\w+)', str(i)).groups()[0]
            except AttributeError:
                protection_level = 'normal'
            description = str(i.find('p').contents[0]).strip()
            if description == "":
                description = permission_name
            online_permissions[permission_name] = [protection_level,description]
        fichier = open("/home/ech0/APAT-server/APAT/apat/data/permissions.json", "w")
        fichier.write(json.dumps(online_permissions))
        fichier.close()
        os.system("curl https://reports.exodus-privacy.eu.org/api/trackers -o /home/ech0/APAT-server/APAT/apat/data/trackers.json 2>/dev/null")
        os.system("wget https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt -O /home/ech0/APAT-server/APAT/apat/data/maltrail-malware-domains.txt 2>/dev/null")
