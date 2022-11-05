from email.policy import default
import os
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import subprocess
import frida
session = None
scriptPath = None
def connectDevice():
    devices = frida.enumerate_devices()
    print("Select device: ")
    print("ID\t\tDevice Name" )
    for device in devices:
        print(device.id+"\t\t"+device.name)
    deviceId = input("Select device with ID (default last device):") or devices[len(devices)-1].id
    return frida.get_device(deviceId)
def selectProcess(device,proc = None):
    if(proc == None):
        procList = sorted(device.enumerate_processes(), key=lambda d: d.name)
        procDict = {}
        for i in procList:
            procDict[i.pid] = i.name 
            print(str(i.pid) + " " + i.name)
        pid  = input("Select process with pid to hook:")
        proc = procDict[int(pid)]
        print("Selected process: " + proc)
    else:
        return device.attach(proc)
    try:
        return device.attach(proc)
    except frida.ServerNotRunningError:
        if (subprocess.Popen("adb -s "+device.id+ ' shell "su -c "/data/local/tmp/frida-server &"', shell=False)):
            return selectProcess(device=device,proc=proc)
        else:
            print("Frida server not started. Please check frida server is exist")
            exit(0)
def selectJsScript():
    jsFilePath  = input("Path to js file (Default hook.js):") or "hook.js"
    return os.path.abspath(jsFilePath)
def runScript(session,scriptPath):
    try:
        scriptContent = open(scriptPath).read()
        scriptContent = 'try{'+scriptContent+'}catch(ex){console.log(ex);}'
        script = session.create_script(scriptContent)
        script.load()
    except FileNotFoundError:
        with open(scriptPath, 'w') as f:
            f.write('console.log("Hello hooker!!")')
        runScript(session,scriptPath)
    except frida.InvalidArgumentError as e:
        print(str(e))
def fileOnModified(event):
    runScript(session,scriptPath)
def createEventHandler(eventFunction):
    eventHandler = PatternMatchingEventHandler(patterns=["*"], ignore_patterns=None, ignore_directories=False, case_sensitive=True)
    eventHandler.on_modified = eventFunction
    return eventHandler
def createObserver(eventHandler,wacthdogDirectory):
    observer = Observer()
    observer.schedule(eventHandler, wacthdogDirectory, recursive=True)
    return observer

if __name__ == "__main__":
    device  = connectDevice()
    session = selectProcess(device)
    scriptPath = selectJsScript()
    runScript(session=session,scriptPath=scriptPath)
    eventHandler = createEventHandler(eventFunction=fileOnModified)
    observer = createObserver(eventHandler=eventHandler,wacthdogDirectory=os.path.dirname(scriptPath))
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()






