from bs4 import BeautifulSoup
import requests as req
import datetime
from apat.log import Log

class InfoApp:

    def __init__(self, p_packages):
        self.packages = p_packages

    def get_trackers(self):
        packages = self.packages
        trackers_list = {}
        for package in packages:
            request = req.get('https://reports.exodus-privacy.eu.org/fr/reports/%s/latest'%package)
            s = BeautifulSoup(request.text, 'html.parser')
            trackers = s.findAll('a', {'class':'link black'})
            trackers_dict = []
            for tracker in trackers:
                tracker = str(tracker)
                tracker = tracker.split('>')
                tracker = tracker[1].split('<')
                trackers_dict.append(tracker[0])
                Log(f"Application: {package} - pisteur: {tracker[0]}")
            trackers_list[package] = trackers_dict
        return trackers_list
            
    def get_permissions(self):
        packages = self.packages
        permissions_list = {}
        for package in packages:
            request = req.get('https://reports.exodus-privacy.eu.org/fr/reports/%s/latest'%package)
            s = BeautifulSoup(request.text, 'html.parser')
            permissions = s.findAll('span', {'data-toggle':'tooltip'})
            permissions_dict = []
            for permission in permissions:
                permission = str(permission)
                permission = permission.split('>')
                permission = permission[1].split('<')
                permissions_dict.append(permission[0])
                Log(f"Application: {package} - permission: {permission[0]}")
            permissions_list[package] = permissions_dict
        return permissions_list

    def get_categorie(self):
        packages = self.packages
        categorie_list = {}
        for package in packages:
            request = req.get('https://play.google.com/store/apps/details?id=%s'%package)
            if request.status_code == 404:
                categorie_list[package] = "Inconnu"
            else:
                categorie = request.text
                categorie = categorie.split('applicationCategory":"')
                categorie = categorie[1].split('","')
                categorie_list[package] = categorie[0]
                Log(f"Application: {package} - catégorie: {categorie[0]}")
        return categorie_list
