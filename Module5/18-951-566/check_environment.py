import subprocess

print("This script checks if the versions of python3, gdb, libc, and ld are correct. If they are not, you might want to reset your VM.\n")
errors = []
python_path = subprocess.check_output("whereis python3", shell=True)
if not python_path.startswith(b'python3: /usr/bin/python3.8'):
    errors.append(f"Path of python: Expected first entry: \"b'/usr/bin/python3.8'\", found first entry: \"{python_path.split(b' ')[1]}\"")

python_hash = subprocess.check_output("sha256sum /usr/bin/python3.8", shell=True)
if not python_hash.startswith(b'11d314dc0e341ba019c2287bd650868be3f34d1c937e5d67f5a284af858ce289'):
    errors.append(f"Hash of python version. Expected: \"b'11d314dc0e341ba019c2287bd650868be3f34d1c937e5d67f5a284af858ce289'\", found: \"{python_hash.split(b' ')[0]}\"")

gdb_path = subprocess.check_output("whereis gdb", shell=True)
if not gdb_path.startswith(b'gdb: /usr/bin/gdb'):
    errors.append(f"Path of GDB: Expected: \"b'/usr/bin/gdb'\", found \"{gdb_path.split(b' ')[1]}\"")

gdb_hash = subprocess.check_output("sha256sum /usr/bin/gdb", shell=True)
if not gdb_hash.startswith(b'c1340015c71b34e1dac7fcc96e3d7488179c0a252b1ea0c311784eccff404489'):
    errors.append(f"Hash of GDB: Expected: \"b'c1340015c71b34e1dac7fcc96e3d7488179c0a252b1ea0c311784eccff404489'\", found: \"{gdb_hash.split(b' ')[0]}\"")

libc_hash = subprocess.check_output("sha256sum /usr/lib/x86_64-linux-gnu/libc-2.31.so", shell=True)
if not libc_hash.startswith(b'09d4dc50d7b31bca5fbbd60efebe4ce2ce698c46753a7f643337a303c58db541'):
    errors.append(f"Hash of libc: Expected: \"b'09d4dc50d7b31bca5fbbd60efebe4ce2ce698c46753a7f643337a303c58db541'\", found: \"{libc_hash.split(b' ')[0]}\"")

ld_hash = subprocess.check_output("sha256sum /usr/lib/x86_64-linux-gnu/ld-2.31.so", shell=True)
if not ld_hash.startswith(b'96493303ba8ba364a8da6b77fbb9f04d0f170cbecbc6bbacca616161bd0f0008'):
    errors.append(f"Hash of ld: Expected: \"b'96493303ba8ba364a8da6b77fbb9f04d0f170cbecbc6bbacca616161bd0f0008'\", found: \"{ld_hash.split(b' ')[0]}\"")

if errors:
    print("There might be one or several issues with your setup:")
    for e in errors:
        print(e)
else:
    print("No issues found.")
