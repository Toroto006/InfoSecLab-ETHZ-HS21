#from cryptodome import *
import os
import subprocess
import signal
from time import sleep
import code
import select

to_kill = []

path = "/home/isl/t2/"
node_prefix = ""
path = "/mnt/hgfs/VMwareMain/ETH/Lab/Module4/Task2/"
node_prefix = "/home/toroto006/Downloads/node-v16.13.0-linux-x64/bin/"

def cleanUp():
    for k in to_kill:
        try:
            os.kill(k, signal.SIGTERM)
            print(f"Kill of {k} successful")
        except:
            pass

def setup() -> subprocess.Popen:
    #os.system("pkill -9 gdb")
    #os.system("pkill -9 string_parser")
    #  Ensure that you start M, P and SP before starting RP to guarantee correct operation
    P = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}peripheral"])
    to_kill.append(P.pid)
    sleep(2)
    E = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}enclave"])
    to_kill.append(E.pid)
    print("Setup done, let's now do the request")

def main():
    setup()
    # Exploit
    #SP.stdin.write(b'r\n')
    #SP.stdin.flush()
    sleep(5)
    #RP = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}remote_party"])
    #to_kill.append(RP.pid)
    to_write = 'set $eax = 0x8da8a1\n'.encode()
    #SP.stdin.flush()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        print(f"An error occured in main!")
    finally:
        cleanUp()
