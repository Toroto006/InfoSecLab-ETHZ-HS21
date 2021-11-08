import os 
import sys

flag21 = "42dae51c29111b61c0ef600f8ff1b54a19c4b80826b1a06cbb580698a9eb957d"
flag22 = "b64604afc083353bfd14c3b3b55734f733a6b3422f683c989e17b532c7471ac3"
flag23 = "33eb30c9a907bc968565dc0796167e47784885d2c1d1dcd7ef94f227b8ccec97"
flag24 = "ddaacbeb70f6dbd7c4512ba2ca98de8b45b6c664c94001d3f2c29e50b8df3072"
flagDict = [("flag-2-1", flag21), ("flag-2-2", flag22), ("flag-2-3", flag23), ("flag-2-4", flag24)] 
name = "grade-2-"
print(len(sys.argv))
if len(sys.argv) > 1:
    name = name + sys.argv[1]
else:
    name = name + '11-111-111'

f = open(name, "w")

f.write("Flag,Points"+ os.linesep)
for d in flagDict:
    if(os.path.isfile(d[0])):
        with open(d[0], "r") as flag:
            flag_gen = flag.readline()
            if d[1] == flag_gen:
                f.write(d[0]+","+str(5) + os.linesep)
        os.remove(d[0])
f.close()

