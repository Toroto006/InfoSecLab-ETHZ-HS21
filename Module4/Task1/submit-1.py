#from cryptodome import *
import os
import subprocess
import signal
from time import sleep
import code
import select

to_kill = []

#path = "/home/isl/t1/"
#node_prefix = ""
path = "/mnt/hgfs/VMwareMain/ETH/Lab/Module4/Task1/"
node_prefix = "/home/toroto006/Downloads/node-v16.13.0-linux-x64/bin/"

def cleanUp():
    for k in to_kill:
        try:
            os.kill(k, signal.SIGTERM)
            print(f"Kill of {k} successful")
        except:
            pass

def setup() -> subprocess.Popen:
    os.system("pkill -9 gdb")
    os.system("pkill -9 string_parser")
    #  Ensure that you start M, P and SP before starting RP to guarantee correct operation
    M = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}manager"])
    to_kill.append(M.pid)
    P = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}peripheral"])
    to_kill.append(P.pid)
    sleep(1)
    SP = subprocess.Popen(["gdb", f"{path}string_parser"], stdin=subprocess.PIPE)
    #SP = subprocess.Popen([f"{path}string_parser"], stdin=subprocess.PIPE)
    to_kill.append(SP.pid)
    print("Setup done, let's now do the request")
    return SP

def main():
    SP = setup()
    # Exploit
    SP.stdin.write(b'set follow-fork-mode child\n')
    SP.stdin.write(b'b* gcm_crypt_and_tag\n')
    SP.stdin.write(b'r\n')
    SP.stdin.flush()
    sleep(1)
    RP = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}remote_party"])
    to_kill.append(RP.pid)
    to_write = 'set {char[42]}0x7fffffffd730 = "<mes><action type=\\"key-update\\"/></mes>"\n'.encode()
    print(to_write)
    SP.stdin.write(b'c\n')
    SP.stdin.write(to_write)
    SP.stdin.write(b'x /s 0x7fffffffd730\n')
    SP.stdin.write(b'c\n')
    SP.stdin.flush()
    sleep(2)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        print(f"An error occured in main!")
    #finally:
    #    cleanUp()