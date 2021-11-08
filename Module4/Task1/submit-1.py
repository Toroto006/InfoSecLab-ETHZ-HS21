#from cryptodome import *
import os
import subprocess
import signal
from time import sleep
import code

to_kill = []

def cleanUp():
    for k in to_kill:
        try:
            os.kill(k, signal.SIGTERM)
            print(f"Kill of {k} successful")
        except:
            pass

def setup() -> subprocess.Popen:
    #  Ensure that you start M, P and SP before starting RP to guarantee correct operation
    M = subprocess.Popen(["node", "--no-warnings", "/home/isl/t1/manager"])
    to_kill.append(M.pid)
    P = subprocess.Popen(["node", "--no-warnings", "/home/isl/t1/peripheral"])
    to_kill.append(P.pid)
    #SP = subprocess.Popen(["/home/isl/t1/string_parser"])
    #to_kill.append(SP.pid)
    print("Setup done, let's now do the request")
    #return SP

def main():
    SP = setup()
    # Exploit
    sleep(2)
    
    # set follow-fork-mode child
    code.interact(local=locals())
    # Let's now try the run
    RP = subprocess.Popen(["node", "--no-warnings", "/home/isl/t1/remote_party"])
    to_kill.append(RP.pid)
    code.interact(local=locals())
    sleep(2)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An error occured in main!")
    finally:
        cleanUp()
