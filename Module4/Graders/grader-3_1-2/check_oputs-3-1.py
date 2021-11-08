import os 
import sys
grade_op = ""
all_passed = True
oput = ["magicbeans,complete", "deadbeef,complete", "badcafe,complete", "pwned,complete", "haxor,complete"]
for i in range(1,6):
    fname = "oput_"+str(i)
    if os.path.isfile(fname):
        with open(fname,"r") as f:
            if(f.readline() == oput[i-1]):
                grade_op = grade_op + "Passed,public " + str(i) + "\n"
            else:
                grade_op = grade_op + "Failed,public " + str(i) + "\n"
                all_passed = False
    else:
        grade_op = grade_op + "No file,public " + str(i) + "\n"
        all_passed = False

if all_passed:
    grade_op = grade_op+"All test cases passed. Your solution will be evaluated on the private test set\n" 
else:
    grade_op = grade_op+"Some test cases failed. Your solution will not be evaluated on the private test set: 0 points!\n"                

name = "grade-3-1-"
print(len(sys.argv))
if len(sys.argv) > 1:
    name = name + sys.argv[1]
else:
    name = name + '11-111-111'

with open(name, "w") as f:
    f.writelines(grade_op)
