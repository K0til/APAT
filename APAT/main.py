#!/usr/bin/python3
from apat.mitm import *
from apat.info_app import *
from apat.update_data import UpdateData
from apat.log import Log
import sys
import json
import requests
import datetime
from flask import Flask
from flask import request
import threading
from pathlib import Path
import os

if len(sys.argv) != 1:
    exit(1)

# Création du dossier de log
if not os.path.exists('/var/log/apat'):
    os.makedirs('/var/log/apat')

# Récupération de la liste des applications
def get_packages_list(ip):
    fichier = open(f"/home/ech0/APAT-server/APAT/packages/{ip}_packages_list", "r")
    packages_list = json.load(fichier)
    fichier.close()
    return packages_list['packages_list']

# Récupération de la liste des applications
def get_packages_start(ip):
    fichier = open(f"/home/ech0/APAT-server/APAT/packages/{ip}_packages_start", "r")
    packages_start = json.load(fichier)
    fichier.close()
    return packages_start['packages_start']

# Lister les domaines en tant que légitime, pisteur ou non légitime
def domaine_legit(dns):
    domaine = {}
    trackers_list_file = open("/home/ech0/APAT-server/APAT/apat/data/trackers.json",)
    trackers_list = json.load(trackers_list_file)
    trackers_list_file.close()
    malwares_list_file = open("/home/ech0/APAT-server/APAT/apat/data/maltrail-malware-domains.txt", "r")
    malwares_list = malwares_list_file.readlines()
    malwares_list_file.close()
    for dom in dns:
        if dom in trackers_list:
            domaine[dom] = "Pisteur"
        else:    
            domaine[dom] = "Legitime"
        for malware in malwares_list:
            if dom in malware:
                domaine[dom] = "Non legitime"
    return domaine

# status
def get_status(packages_list, packages_start):
    status = {}
    for package in packages_list:
        if package in packages_start:
            status[package] = "En cours"
        else:
            status[package] = "Eteinte"
    return status

# Création du résultat en json
def create_json(packages_list, permissions, categorie, trackers, domaine, status):
    data = {}
    permissions_list_file = open("/home/ech0/APAT-server/APAT/apat/data/permissions.json",)
    permissions_list = json.load(permissions_list_file)
    permissions_list_file.close()
    for package in packages_list:
        permissions_list_l1 = {}
        if permissions[package] == []:
            permissions_list_l1 = ""
        else:
            for permission in permissions[package]:
                permissions_list_l2 = {}
                if permission not in permissions_list:
                    permissions_list_l2["Niveau de securite"] = "normal"
                    permissions_list_l2["Description"] = str(permission)
                    permissions_list_l1[permission] = permissions_list_l2
                else:
                   permissions_list_l2["Niveau de securite"] = str(permissions_list[permission][0])
                   permissions_list_l2["Description"] = str(permissions_list[permission][1])
                   permissions_list_l1[permission] = permissions_list_l2
        data[package] = {"Status":status[package],"Categorie":categorie[package], "Pisteurs":trackers[package], "Autorisations":permissions_list_l1}
    data["domaine"] = domaine
    return data

# Création du fichier json
def create_json_file(ip, data):
    report_file = f"/home/ech0/APAT-server/APAT/reports/{ip}_{report_name[ip]}"
    out = open(report_file, "w")
    out.write(json.dumps(data))
    out.close()

def start_analyze(ip, thread):
    tid = f"{ip} - thread: {thread}"
    UpdateData()
    Log(tid+" --> Données du serveur mises à jour")
    packages_list = get_packages_list(ip)
    Log(tid+" --> Liste des applications du téléphone récupérée")
    packages_start = get_packages_start(ip)
    Log(tid+" --> Liste des applications en cours d'exécution récupérée")
    Log(tid+" --> MITM en cours...")
    scan = Mitm("tun0", ip, 60)
    capture = scan.capture()
    dns = scan.get_dns(capture)
    Log(tid+" --> MITM fini")
    info = InfoApp(packages_list)
    Log(tid+" --> Récupération des pisteurs pour les applications...")
    trackers = info.get_trackers()
    Log(tid+" --> Fait")
    Log(tid+" --> Récupération des permissions pour les applications...")
    permissions = info.get_permissions()
    Log(tid+" --> Fait")
    Log(tid+" --> Récupération des catégories pour les applications...")
    categorie = info.get_categorie()
    Log(tid+" --> Fait")
    Log(tid+" --> Classement des domaines")
    domaine = domaine_legit(dns)
    Log(tid+" --> Fait")
    Log(tid+" --> Récupération des status pour les applications")
    status = get_status(packages_list, packages_start)
    Log(tid+" --> Fait")
    Log(tid+" --> Génération du rapport...")
    data = create_json(packages_list, permissions, categorie, trackers, domaine, status)
    Log(tid+" --> Rapport généré")
    create_json_file(ip, data)

# API
app = Flask(__name__)
@app.route("/start", methods=["GET"])
def start():
    ip = request.remote_addr
    Log(ip+" -> GET /start")
    date = datetime.datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    global report_name
    report_name = {}
    report_name[ip] = date
    analyze = threading.Thread(target=start_analyze, args=(ip,report_name[ip],), name=report_name[ip])
    analyze.start()
    Log(f"{ip} - thread: {report_name[ip]} --> Analyse en cours")
    return "Analyse en cours.\n"

@app.route("/status", methods=["GET"])
def status():
    ip = request.remote_addr
    Log(ip+" -> GET /status")
    if 'report_name' in globals():
        if ip in report_name:
            for thread in threading.enumerate():
                if report_name[ip] in str(thread):
                    Log(ip+" --> L'analyse est encore en cours")
                    return "L'analyse est encore en cours.\n"
            Log(ip+" --> L'analyse est finie")
            return "L'analyse est finie.\n"
        else:
            Log(ip+" --> L'analyse n'a pas encore été lancée")
            return "L'analyse n'a pas encore été lancée.\n"
    else:
        Log(ip+" --> L'analyse n'a pas encore été lancée")
        return "L'analyse n'a pas encore été lancée.\n"

@app.route("/upload_packages_list", methods=["POST"])
def upload_packages_list():
    data = request.get_json()
    ip = request.remote_addr
    Log(ip+" -> POST /upload_packages_list")
    if data != None:
        fichier = open(f"/home/ech0/APAT-server/APAT/packages/{ip}_packages_list", "w")
        fichier.write(json.dumps(data))
        fichier.close()
        Log(ip+" --> Données bien uploadées")
        return "Données bien uploadées.\n"
    else:
        Log(ip+" --> Aucune données reçu")
        return "Aucune données reçu.\n"

@app.route("/upload_packages_start", methods=["POST"])
def upload_packages_start():
    data = request.get_json()
    ip = request.remote_addr
    Log(ip+" -> POST /upload_packages_start")
    if data != None:
        fichier = open(f"/home/ech0/APAT-server/APAT/packages/{ip}_packages_start", "w")
        fichier.write(json.dumps(data))
        fichier.close()
        Log(ip+" --> Données bien uploadées")
        return "Données bien uploadées.\n"
    else:
        Log(ip+" --> Aucune données reçu")
        return "Aucune données reçu.\n"

@app.route("/get_report", methods=["GET"])
def get_report():
    ip = request.remote_addr
    Log(ip+" -> GET /get_report")
    if 'report_name' in globals():
        if ip in report_name:
            report_file = f"/home/ech0/APAT-server/APAT/reports/{ip}_{report_name[ip]}"
            if Path(report_file).is_file():
                fichier = open(report_file, "r")
                data = fichier.read()
                fichier.close()
                Log(ip+" --> Données bien transmises")
                return json.dumps(data)
            else:
                Log(ip+" --> L'analyse n'est pas encore fini")
                return "L'analyse n'est pas encore fini.\n"
        else:
            Log(ip+" --> L'analyse n'a pas encore été lancée")
            return "L'analyse n'a pas encore été lancée.\n"
    else:
        Log(ip+" --> L'analyse n'a pas encore été lancée")
        return "L'analyse n'a pas encore été lancée.\n"

if __name__ == '__main__':
    app.run(host="10.8.0.1", port=9793)
