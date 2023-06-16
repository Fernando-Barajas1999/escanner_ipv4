class networkScanner:

    def __init__(self, ip="", initialRange=1, finalRange=254):
        self.ip = ip
        self.initialRange = initialRange
        self.finalRange = finalRange
        self.activeIps = []
        self.network = ""
        self.scanInitialTime = 0
        self.scanFinalTime = 0

    #------------------ /// FUNCIONES PARA RETORNAR LOS VALORES (IP, RANGO INICIAL Y FINAL) /// ------------------
    def getIp(self):
        return self.ip
    
    def getInitialRange(self):
        return self.initialRange

    def getFinalRange(self):
        return self.finalRange
    
    def getActiveIps(self):
        return self.activeIps

    def getNetwork(self):
        return self.network    

    def getScanDuration(self):
        return self.scanFinalTime - self.scanInitialTime
    
    def getValues(self):
        return {"ip" : self.ip,
                "Initial range" : self.initialRange, 
                "Final range": self.finalRange,
                "network" : self.network,
                "activeips" : self.activeIps,
                "scan duration" : self.getScanDuration()}
    
    #------------------ /// FUNCIONES PARA OBTENER EL TIEMPO Y CALCULAR LA DURACION DEL ESCANEO  /// ------------------
    def getTime(self):
        from datetime import datetime
        return datetime.now()
    
    #------------------ /// FUNCIONES PARA ESTABLECER NUEVO VALOR DE IP  /// ------------------
    def setIp(self, ip):
        self.ip = ip
    
    def setInitialRange(self, initial):
        self.initialRange = initial

    def setFinalRange(self, final):
        self.finalRange = final

    def setActiveIps(self, activeIps):
        self.activeIps = activeIps

    def setScanInitialTime(self, time):
        self.scanInitialTime = time
    
    def setScanFinalTime(self, time):
        self.scanFinalTime = time

    def setNetwork(self, ip):
        self.network = ".".join(ip.split(".")[0:3]) #obtenemos los cuartetos de la ip y tomamos los 3 primeros

    #------------------ /// FUNCIONES PARA REVISAR SI ALGUN VALOR ESTA NULO Y COLOCAR UNO PREDETERMINADO  /// ------------------
    def checkNullValues(self):
        if self.getIp() == "":
            
            #check the SO
            match self.detectSO():
                #To take the ip prederminate from the SO
                #If the first method fail, it'll use a second methond
                case "Windows":
                    self.setIp( self.getIPWindowsSubprocessRun() )  
                case "Linux":
                    self.setIp( self.getIPLinuxSubprocessRun() ) 
                case "Darwin":
                    self.setIp( self.getIPMacSubprocessRun() ) 

        if not self.getIp():
            self.setIp( self.getIPWindowsScoket() )     

        #To set the network from the ip obtained   
        self.setNetwork(self.getIp())

        #To set the prederminate range if the user's input is null
        if self.getInitialRange() == "" :
            self.setInitialRange(1)
        if self.getFinalRange() == "" :
            self.setFinalRange(254)

    #------------------ /// FUNCION PARA COMENZAR EL ESCANEO  /// ------------------
    def startScanner(self):
        print("Starting scan...")
        self.checkNullValues()
        self.setScanInitialTime(self.getTime()) 
        self.networkScanner()
        self.setScanFinalTime(self.getTime())
        self.formatMacArp(self.getMacArp())
        self.showResult()
        
    #------------------ /// ------------------ PARA DETECTAR EL SISTEMA OPERATIVO DEL USUARIO ------------------ /// ------------------
    def detectSO(self):
        import platform
        #windows = Windows, linux = Linux, mac = Darwin
        return platform.system()

    #------------------ /// FUNCION PARA OBTENER LA IP DE WINDOWS A TRAVES DE SOCKET /// ------------------
    def getIPWindowsScoket(self):
        import socket 
        return socket.gethostbyname(socket.gethostname())
    
    #------------------ /// FUNCION PARA OBTENER LA IP DE WINDOWS A TRAVES DE SUBPROCESS CON RUN/// ------------------
    def getIPWindowsSubprocessRun(self):
        import subprocess
        import sys
        cmd = "ipconfig | findstr IPv4" #comando ifconfig y filtramos la salida para solo obtener la ip
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return result.stdout.split(":")[1].strip()
        else:
            print(f"command {result.stdout} return with error (code {result.returncode}): {result.stderr}")
            return False

    #------------------ /// FUNCION PARA OBTENER LA IP DE LINUX A TRAVES DE SUBPROCESS CON RUN/// ------------------
    def getIPLinuxSubprocessRun(self):
        import subprocess
        import sys
        cmd = "hostname -I" 
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return result.stdout
        else:
            print(f"command {result.stdout} return with error (code {result.returncode}): {result.stderr}")
            return False
    
    #------------------ /// FUNCION PARA OBTENER LA IP DE MAC A TRAVES DE SUBPROCESS CON RUN/// ------------------
    def getIPMacSubprocessRun(self):
        import subprocess
        import sys
        cmd = "ipconfig getifaddr en0" #comando ifconfig y filtramos la salida para solo obtener la ip
        cmd2 = "hostname -I" 
        result = subprocess.run(cmd2, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return result.stdout.split(" ")[0]
        else:
            print(f"command {result.stdout} return with error (code {result.returncode}): {result.stderr}")
            return False

    #------------------ /// ------------------ REALIZAR PING A CIERTA IP ------------------ /// ------------------
    def ping(self, command, ip):
        import subprocess
        return subprocess.run(f"{command} {ip}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    #------------------ /// ------------------ REALIZAR ESCANEO DE LA RED ------------------ /// ------------------
    def networkScanner(self):

        #Depending the SO, the command for ping will change
        match self.detectSO():
            #n = number of request, w = amount of time to wait the reply
            case "Windows":
                commandPing = "ping -n 1 -w 1"
            case "Linux" | "Darwin" :
                commandPing = "ping -c 1 -w 1"
        
        #list to save the active ips
        activeIps = [] 
        
        #ping to every ip in the range
        for i in range(self.getInitialRange(), self.getFinalRange()):
            
            ip_check = self.getNetwork() + "." + str(i)
            if(self.ping(commandPing, ip_check)):
                activeIps.append(ip_check)
        
        #if our ip is in the list, we remove it
        # if self.getIp() in activeIps:
        #     activeIps.remove(self.getIp())
        
        self.setActiveIps(activeIps) 
    
    #------------------ /// ------------------ DAR FORMATO AL RESULTADO DE ARP -A ------------------ /// ------------------
    def formatMacArp(self, table):
        import re
        regex = '(?:'+str(self.getNetwork())+'.*(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2}))' #regular expression for ip and mac in the same line
        matches=re.findall(regex, table) #get the matches lines from the arp table
        matches = [item.split() for item in matches] #separe the matches for get the ip and mac 
        
        activeIps = self.getActiveIps() #get the ip actives
        newList = []
        #put the mac in the active ips list
        for data in matches:
            ip = data[0]
            if ip in activeIps:
                newList.append({'ip' : ip, 'mac' : data[1]})

        self.setActiveIps(newList)
        

    #------------------ /// ------------------ OBTENER LAS MAC A TRAVÉS DEL COMANDO ARP -A ------------------ /// ------------------
    def getMacArp(self):
        import subprocess
        match self.detectSO():
            case "Windows":
                command = f"arp -a | findstr /r ^{self.getNetwork()}"
            case "Linux" | "Darwin":
                command = "arp -n | awk '{print $1, $3}'"
        
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return result.stdout
        else:
            print(f"command {result.stdout} return with error (code {result.returncode}): {result.stderr}")
            return False
    
    # #------------------ /// ------------------ MOSTRAR RESULTADO FINAL ------------------ /// ------------------
    def showResult(self):
        print("-"*60)
        print(f"IP: {self.getIp()}")
        print(f"Initial range Scan: {self.getInitialRange()}")
        print(f"Final range Scan: {self.getFinalRange()}")
        print(f"Scan duration time: {self.getScanDuration()}")
        print(f"Active IP's: {len(self.getActiveIps())}")
        print("-"*60)
        headers = [
            'ID',
            'IP Address',
            'MAC Address'
        ]

        print(f'\n{headers[0]: <10}{headers[1]: <20}{headers[2]}')
        for indice, data in enumerate (self.getActiveIps()):
            print(f'{indice: <10}{data["ip"]: <20}{data["mac"]}')
