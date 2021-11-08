import csv
import os.path
import sys

f_ok = True
t_ok = True
tuples = []

op = ""
if os.path.isfile("./forked"):
    op = "Public Tests, failed (forked), 0 Points"
else:
    if os.path.isfile("functionality.csv") and os.path.isfile("diff_traces.csv"):
        with open('functionality.csv') as f:
            reader = csv.reader(f)
            tuples = [tuple(row) for row in reader]

        tuples = tuples[1:]
        for row in tuples:
            if row[0] == row[1] and row[2] != '1':
                f_ok = False
                #print(row[0], row[1], row[2])
                break
            elif row[0] != row[1] and row[2] != '0':
                f_ok = False
                #print(row[0], row[1], row[2])
                break

        if f_ok:
            with open('diff_traces.csv') as f:
                reader = csv.reader(f)
                tuples = [tuple(row) for row in reader]
            tuples = tuples[1:]
            z = [int(row[4]) for row in tuples]
            if sum(z) != 0:
                t_ok = False

        if f_ok and t_ok:
            op = "Public Tests, passed, 5 Points"
        else:
            op = "Public Tests, failed, 0 Points"
    else:
        op = "Public Tests, failed (functionality.csv or/and diff_traces.csv not found), 0 Points"
name = "grade-3-3-"
print(len(sys.argv))
if len(sys.argv) > 1:
    name = name + sys.argv[1]
else:
    name = name + '11-111-111'

with open(name, "w") as f:
    f.writelines(op)
