import os
import subprocess
import signal
from time import sleep

to_kill = []

path = "/home/isl/t1/"
node_prefix = ""

def cleanUp():
    for k in to_kill:
        try:
            os.kill(k, signal.SIGTERM)
            print(f"Kill of {k} successful")
        except:
            pass

def setup() -> subprocess.Popen:
    M = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}manager", "&"])
    to_kill.append(M.pid)
    P = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}peripheral", "&"])
    to_kill.append(P.pid)
    sleep(2)
    SP = subprocess.Popen([f"{path}string_parser"], stdin=subprocess.PIPE)
    to_kill.append(SP.pid)
    print("Setup done, let's now do the request")
    return SP

def main():
    SP = setup()
    sleep(2)
    RP = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}remote_party"])
    to_kill.append(RP.pid)
    sleep(10)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        print(f"An error occured in main!")
    #finally:
        #cleanUp()
