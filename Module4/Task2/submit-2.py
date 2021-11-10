#from cryptodome import *
import os
import subprocess
import signal
from time import sleep
import code
import select
import requests
from requests.exceptions import ConnectionError

path = "/home/isl/t2/"
node_prefix = ""
#path = "/mnt/hgfs/VMwareMain/ETH/Lab/Module4/Task2/"
#node_prefix = "/home/toroto006/Downloads/node-v16.13.0-linux-x64/bin/"

enclave_uri = "http://127.0.0.1:37100"
peripheral_uri = "http://127.0.0.1:37200"

def cleanUp():
    os.system("pkill -9 node")

def setup() -> subprocess.Popen:
    #  Ensure that you start M, P and SP before starting RP to guarantee correct operation
    P = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}peripheral"], stdin=subprocess.PIPE,  stdout=subprocess.PIPE)
    sleep(1)
    E = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}enclave"], stdin=subprocess.PIPE,  stdout=subprocess.PIPE)
    sleep(2)
    print("Setup done, let's now do the request")
    return P, E

def readuntil(w, s, name):
    line = ""
    while s not in line:
        line = w.stdout.readline().decode().rstrip()
        print(f"{name}<{line}")
    return s

def injectHello(P):
    readuntil(P, "Store takes some time", "PwaitS")
    msg = '<start_messages><mes cd="hello"></mes></start_messages>'
    try:
        rep = requests.post(f"{peripheral_uri}/AAAA")
        if rep.status_code == 200:
            print(f"P req returned {rep.text}")
        else:
            print(f"P got {rep}")
    except ConnectionError:
        print("ERROR: An error occurred")

def main():
    P, E = setup()
    # Exploit
    injectHello(P)
    #readuntil(E, "Enclave connected", "E")

if __name__ == "__main__":
    cleanUp()
    try:
        main()
    except Exception as e:
        print(e)
        print(f"An error occured in main!")
    finally:
        cleanUp()
    #os.system("cd /home/isl/t2 && /home/isl/t2/run.sh")
    print("Exploit done")
    exit()
