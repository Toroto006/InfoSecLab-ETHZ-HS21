import os 
import subprocess
import time 

def wipe_all_running():
    os.system("pkill -9 node")
    os.system("pkill -9 string_parser")
    os.system("pkill -9 gdb")
    time.sleep(2)
    return 
    
def start_manager_and_peripheral():
    os.system("cd /home/isl/t1  && /home/isl/t1/run_manager.sh ") # | tee  /home/isl/t1/manager.log &")
    os.system("cd /home/isl/t1  && /home/isl/t1/run_peripheral.sh ") # | tee  /home/isl/t1/peripheral.log &")
  #  os.system("cd /home/isl/t1 && /home/isl/t1/run.sh")
    os.system("pkill -9 string_parser")
    return 
    
def write(process,str):
    string = (str + "\n").encode()
    time.sleep(1)
    process.stdin.write(string)
    process.stdin.flush() 
    return

def partOne(): #https://stackoverflow.com/questions/32978233/invoke-gdb-from-python-script
    gdb = subprocess.Popen(["gdb", "screen"], stdin=subprocess.PIPE) #/home/isl/t1/string_parser"], stdin=subprocess.PIPE)
    time.sleep(1)
#    write(gdb,"set detach-on-fork off")s
    write(gdb,"set follow-fork-mode child")
    write(gdb,"set breakpoint pending on")
    write(gdb,"break gcm_crypt_and_tag")
    write(gdb,"run -dmS string_parser /home/isl/t1/string_parser")
    time.sleep(1)
    os.system("node --no-warnings /home/isl/t1/remote_party  | tee /home/isl/t1/remote_party.log &")
    write(gdb,"break gcm_crypt_and_tag")
    write(gdb,"continue")
    write(gdb,"print input")
    write(gdb,'set {char[40]} input = "<mes><action type=\\"key-update\\"/></mes>" ')
    write(gdb,"print input")
    write(gdb,"continue 100")
    time.sleep(2)
   # print("MANAGER LOGS")
   # print("===============================")    
   # os.system("cat /home/isl/t1/manager.log")
   ## print("===============================")    
   # print("PERIPHERAL LOGS")
   # print("===============================")    
   # os.system("cat /home/isl/t1/peripheral.log")
   # print("===============================")    
   # print("TERMINATING GDB")
#    os.system("python3 /home/isl/t1/test_setup.py")
    gdb.terminate()
    os.system("pkill -9 gdb")
    return 
    
def partTwo():
    os.system("pkill -9 gdb")
    os.system("pkill -9 string_parser")
    gdb = subprocess.Popen(["gdb", "screen"], stdin=subprocess.PIPE) #/home/isl/t1/string_parser"],
    time.sleep(1)
    write(gdb,"set follow-fork-mode child")
    write(gdb,"set breakpoint pending on")
    write(gdb,"break stringParser")
    write(gdb,"run -dmS string_parser /home/isl/t1/string_parser")
    #write(gdb,"set detach-on-fork off")
    #write(gdb,"set follow-fork-mode child")
   
    write(gdb,"break *0x040338a")
    write(gdb,"continue")
    #write(gdb,"run")
    time.sleep(1)
    os.system("node --no-warnings /home/isl/t1/remote_party | tee /home/isl/t1/remote_party.log &")
    time.sleep(1)
    write(gdb,"set redirectAdmin = 0x8da8a1")
    write(gdb,"break *0x04033de")
    write(gdb,"continue")
    write(gdb,"set $rax = redeemer[2]")
    write(gdb,"break *0x4033fb")
    write(gdb,"continue")
    write(gdb,"set $al = 0x13")
    write(gdb,"continue")
    time.sleep(2)
#    print("MANAGER LOGS")
#    print("===============================")        
#    os.system("cat /home/isl/t1/manager.log")
#    print("===============================")    
#   print("PERIPHERAL LOGS")
#    print("===============================")    
#    os.system("cat /home/isl/t1/peripheral.log")
#    print("===============================")    
#    print("TERMINATING GDB")
    gdb.terminate()
    os.system("pkill -9 gdb")	
    return 



wipe_all_running()
start_manager_and_peripheral()
partOne() 

###Following are just needed to make function return nicely. 
partTwo()
#time.sleep(100)
#print("TERMINATING")
wipe_all_running()
os.system("cd /home/isl/t1 && /home/isl/t1/run.sh")


