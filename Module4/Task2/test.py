import glob
import os
import time

def splitM(m):
    contt = m[:16]
    ts = m[16:2*16]
    print(f"content type: {contt}")
    print(f"timestamp: {ts}")
    mac = m[2*16:2*16+64]
    print(f"MAC: {mac}")
    hexenc = m[2*16+64:2*16+64+256]
    assert len(hexenc) == 256
    #print(f"AES CBC len: {len(hexenc)}")
    iv = hexenc[:32]
    hexenc = hexenc[32:]
    print(f"IV: {iv}")
    print(f"hexenc without IV: {hexenc}")
    print(f"formatted for replay: {contt}{{ts}}{mac}{iv}{hexenc}\n")

for filename in glob.glob(os.path.join("/home/isl/t2/share/Module4/", 'store*.out')):
    print(filename)
    with open(os.path.join(os.getcwd(), filename), 'r') as f: # open in readonly mode
        hexstream = f.readline().rstrip()
        s = bytes.fromhex(hexstream)[132:].decode().rstrip().split('\n') # 132 is the garbage before
        #print(f"{bytes.fromhex(hexstream)}\n")
        splitM(s[-1])

ts = str(int(time.time()*1000))+"$00"
assert len(ts) == 16
msg = f'hello$0000000000{ts}0389289a839f8104a19535a57c60be21c2da9312df51308e0cd363ba82885b51111111111111111111111111111111112880ccda64f655478e053e178a2b4caf3441570c37c51e5eddeb4fd3f5a15d94653de7101e9c59229b666124029fc7d2dbf080223cc1e27635e9ea1f374e44bf86208d23fe97661d97ed63d5b1585afed679e7d2855f55d403e71c50ebe0390207d926be16293d3d2aa55e6ea6d9f013'
assert len(msg) == 352
