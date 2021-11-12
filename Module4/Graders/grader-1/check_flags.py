# Grading Task 1
# We Use a VM that uses a different Master Key in the Peripheral to produce the Flags field
# Therefore: check if the Useput is correct

import hashlib
import subprocess
import sys


def calc_flag_t1(userID, mode):
    return "fd80176c50cfd9a5ef7586ac848e413a278f8ef7"

def calc_flag_t2(userID, mode):
    return "ee2acaa6c0663a77b2a0b1f724f57b84e93076b3"


def grading_t1(userID):
    #opening_command = "timeout 60 python3 /home/isl/scripts/submit-1.py"
    #p = subprocess.Popen(some_command, stdout=subprocess.PIPE, shell=True)
    #(output, err) = p.communicate()
    #p_status = p.wait()
    flag_1_orig = calc_flag_t1(userID,0)
    flag_2_orig = calc_flag_t2(userID,0)
    print("FLAG 1- EXPECTED: " + flag_1_orig)
    print("FLAG 2- EXPECTED: " + flag_2_orig)
    
    fileoutput = ""
    status = ""
    points = 0

    status = "Grading Task 1; Mat-Nr: " + str(userID)
    fileoutput = fileoutput + status + "\n"
    print(status)

    #Testing for first Flag
    try:
        f = open("./flag1-1", "r")
        flag = f.readline()
        print("FLAG 1 READ: "+ flag)
        if flag_1_orig in flag:
            status = "T1_1: Correct Result - 10P"
            fileoutput = fileoutput + status + "\n"
            points = points + 10
            print(status)
        else:
            status = "T1_1: Invalid Flag - 0P"
            fileoutput = fileoutput + status + "\n"
            print(status)
        f.close()
    except IOError:    #This means that the file does not exist (or some other IOError)
        status = "T1_1: Error opening Flag File - 0P"
        fileoutput = fileoutput + status + "\n"
        print(status)
    except:
        status = "T1_1: Error during Flag validation - 0P"
        fileoutput = fileoutput + status + "\n"
        print(status)

    #Testing for second flag
    try:
        f = open("./flag1-2", "r")
        flag = f.readline()
        print("FLAG 2 READ: " + flag)
        if flag_2_orig in flag:
            status = "T1_2: Correct Result - 15P"
            fileoutput = fileoutput + status + "\n"
            points = points + 15
            print(status)
        else:
            status = "T1_2: Invalid Flag - 0P"
            fileoutput = fileoutput + status + "\n"
            print(status)
        f.close()
    except IOError:    #This means that the file does not exist (or some other IOError)
        status = "T1_2: Error opening Flag File - 0P"
        fileoutput = fileoutput + status + "\n"
        print(status)
    except:
        status = "T1_2: Error during Flag validation - 0P"
        fileoutput = fileoutput + status + "\n"
        print(status)

        
        
    #Testing for Healthcheck
    try:
        f = open("./testlog.otp")
        lines = f.readlines()
        ret = 0
        for line in lines:
            if "Manager HealthCheck successful!" in line:
                ret = 1
                break
        if (ret == 0):
            raise Exception("Manager not online!")
        
        ret = 0
        for line in lines:
            if "Peripheral HealthCheck successful!" in line:
                ret = 1
                break
        if (ret == 0):
            raise Exception("Peripheral not online!")
        
        ret = 0
        for line in lines:
            if "StringParser HealthCheck successful!" in line:
                ret = 1
                break
        if (ret == 0):
            raise Exception("StringParser not online!")
        
        f.close()

        status = "All Healtchecks successful!"
        fileoutput = fileoutput +status + "\n"

    except Exception as e:
        status = str(e)
        print(e)
        fileoutput = fileoutput + status + "\n"
        status = "Healthcheck unsuccessful - task failed, deducting all points (" + str(points) + ")"
        fileoutput = fileoutput + status + "\n"
        points = 0
        print(status)

    status = "SUM: " + str(points) + " points"
    fileoutput = fileoutput + status + "\n"
    print(status)
    
    try:
        gradingOutputLog = open("./grade-t1-" + str(userID), 'w')
        gradingOutputLog.write(fileoutput)
        gradingOutputLog.close()
        print("Wrote grade file to ./grade-t1-" + str(userID))
    except IOError:
        print("ERROR while writing gradeFile; Task is NOT graded successfully!")

id = sys.argv[1]
print(id)
grading_t1("11-111-111")