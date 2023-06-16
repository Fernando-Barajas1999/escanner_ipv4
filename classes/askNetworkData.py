class usersData:

    #------------------ /// ------------------ PREGUNTAR EL RANGO A ESCANEAR ------------------ /// ------------------
    def askRange(self, messageInput):
        while True:
            print(messageInput)
            
            try:
                range = input()
                #if the range is null, we return it for avoid the next numeric validation
                if range == "":
                    return range
                else:
                    range = int(range)  #check that the input is a number
            except ValueError:
                print("Invalid input.")
            else:
                if 1 <= int(range) <= 254: #check that range
                    return range
                else:
                    print("Out of range (it should be 1-254)")
    
    #------------------ /// ------------------ PREGUNTAR LA IP ------------------ /// ------------------
    def askIP(self):
        import re
        while True:
            print("Write ip: (if is null,  your ip will be predeterminate):")
            try:
                ip = input()
                if not re.search('(^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$)|^$', ip):
                    raise Exception()
            except Exception:
                print("Ip address format is not validate")
            else:
                #if the ip is null, we return it for avoid the next numeric validation
                if ip == "":
                    return ip
                else:
                    #check that range for every byte of the ip address
                    segments = ip.split(".")
                    cont = 0
                    for ip_segment in segments:
                        if 0 <= int(ip_segment) <= 255: 
                            cont += 1
                        else:
                            break
                    if cont == 4: #every byte is valid
                        return ip
                    else:   
                        print("Out of range (it should be 1-255)")
    
    #------------------ /// ------------------ VALIDAR QUE EL RANGO INICIAL SEA MENOR O IGUAL AL FINAL ------------------ /// ------------------
    def validateInitialLessFinal(self, initial, final):
        if initial == "" or final == "":
            return True
        return initial<=final
