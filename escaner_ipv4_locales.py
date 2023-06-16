from classes.askNetworkData import usersData
from classes.scanner import networkScanner

#------------------ /// ------------------ MAIN ------------------ /// ------------------
if __name__ == "__main__":

    data = usersData()

    #get the user's initial data
    messageInitialRange = "Write the initial range of ip for the scanner: (if is null, the inicial range will be 1):"
    messageFinalRange = "Write the final range of ip for the scanner: (if is null, the final range will be 254):"
   
    ip = data.askIP()
    initialRange = data.askRange(messageInitialRange)
    finalRange = data.askRange(messageFinalRange)


    while not data.validateInitialLessFinal(initialRange, finalRange):
        print("The initial range should be less or equal to the final range")
        initialRange = data.askRange(messageInitialRange)
        finalRange = data.askRange(messageFinalRange)
    
    #start the network scanner
    scanner = networkScanner(ip, initialRange, finalRange)
    scanner.startScanner()




    


