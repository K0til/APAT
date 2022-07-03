import datetime

class Log:

    def __init__(self, log):
        date = datetime.datetime.now().strftime("%d-%m-%Y")
        datelog = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S - - ")
        logfile = ("apat-"+date)
        fichier = open(f"/var/log/apat/{logfile}.log", "a")
        fichier.write("\n"+datelog+log)
        fichier.close()

