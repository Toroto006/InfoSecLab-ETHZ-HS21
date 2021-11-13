import sys
import os
import glob

# No ASLR so these are fix
input_done_add =        "401183"
comparision_true_add =  "4011B6"
end_loop_add =          "4011C0"
comparision_false_add = "4011BC"
equal_true_add =        "4011D7"
correct_add =           "40134B"
wrong_add =             "401357"

def blocking_on(addresses, stop_block):
    blocks = []
    block = []
    for add in addresses:
        block.append(add)
        if stop_block.lower() in add:
            blocks.append(block)
            block = []
    blocks.append(block)
    return blocks

def parse_interesting(filename):
    addresses = []
    #print(f"Doing {filename}")
    with open(filename, "r") as trace:
        for line in trace:
            if "E:" in line and ":C:" in line:
                # we have an execution line
                addresses.append(line.split(':')[1])
    guesses = []
    start_blocks = blocking_on(addresses, input_done_add)
    # start blocks has two lists, 0 is the one with the len check, 1 with the for loop
    assert len(start_blocks) == 2
    start, comp = start_blocks

    # These are the comparision blocks
    comp_blocks = blocking_on(comp, end_loop_add)
    # prepare guess string
    name = os.path.basename(filename)[:-6] #.guess
    underscores = False
    for i, cmp_blk in enumerate(comp_blocks[:-1]):
        if comparision_true_add.lower() in ''.join(cmp_blk):
            guesses.append(name[i])
            #print(f"Direct guess {name[i]}")
        elif comparision_false_add.lower() in ''.join(cmp_blk):
            guesses.append('_')
            #print(f"Wrong guess {name[i]}")
            underscores = True

    # last comp_block has to contain either correct or false, otherwise trace incomplete
    last_block = comp_blocks[-1]
    correct = None
    for add in last_block:
        if correct_add.lower() in add:
            correct = True
            break
        if wrong_add.lower() in add:
            correct = False
            break
    assert correct is not None # only true if one found
    # Check if I have enough data
    if (equal_true_add.lower() in ''.join(last_block) and len(guesses) == len(name)) or len(guesses) < len(name):
        # The return does a comparision with an &&, where the && lets us check it
        if underscores:
            return guesses, True, True
        return guesses, True, False
    # We did not check a long enough 
    if underscores:
        return guesses, False, True
    return guesses, False, False

def pinRun():
    path_folder = "/home/sgx/isl/t2/"
    for i in range(ord('a'), ord('z')+1):
        guess = chr(i)*35 # let's do 5 more than necessary
        filename = f"{path_folder}{guess}.guess"
        runPin = f"cd /home/sgx/pin-3.11-97998-g7ecce2dac-gcc-linux-master/source/tools/SGXTrace && ../../../pin -t ./obj-intel64/SGXTrace.so -o {filename} -trace 1 -- ~/isl/t2/password_checker_2 {guess}"
        os.system(runPin)
    return path_folder

def runPaths(path_folder):
    best_guess = []
    b_long_enough = False
    for filename in glob.glob(os.path.join(path_folder, '*.guess')):
        guesses, long_enough, underscores = parse_interesting(filename)
        if long_enough and not underscores:
            # we guessed it completely
            return guesses, False
        if long_enough:
            b_long_enough = True
        # Combine the guesses
        sum_guess = best_guess
        adder = guesses
        if len(guesses) > len(best_guess):
            adder = best_guess
            sum_guess = guesses
        for i, c in enumerate(adder):
            if c != '_':
                sum_guess[i] = c
        best_guess = sum_guess
    if b_long_enough and '_' not in ''.join(best_guess):
        return best_guess, False
    return best_guess, True

def main():
    if len(sys.argv) != 2:
        print(f"This code expects a single arguments! arg1: /path/to/traces/folder")
    id = sys.argv[1]
    # Run pin
    path_folder = pinRun()
    #path_folder = "./traces"
    output = f"/home/sgx/isl/t2/output/oput_{id}"
    #output = f"oput_{id}"
    #print(f"Running on {path_folder} with {id} and output to {output}")
    guess, partial = runPaths(path_folder)
    guess_s = ''.join(guess)
    #print(f"Found {guess_s} with partial {partial}")
    out_s = f"{guess_s},{'partial' if partial else 'complete'}"
    #print(f"Wrote {out_s}")
    with open(output, "w") as out:
        out.writelines(out_s)
    os.system("rm /home/sgx/isl/t2/*.guess")

if __name__ == "__main__":
    main()