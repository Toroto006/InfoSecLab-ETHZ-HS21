import sys
import os
import glob

# No ASLR so these are fix
input_done_add =        "401183"
comparision_true_add =  "4011B6"
end_loop_add =          "4011C0"
wrap_j_hit_add =        "4011BC"
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
    name = os.path.basename(filename)[:-4]
    for i, cmp_blk in enumerate(comp_blocks[:-1]):
        if comparision_true_add.lower() in ''.join(cmp_blk):
            guesses.append(name[i])
        else:
            #guesses.append('_')
            # So we missed the first, let's count how many j's, i.e. how far is the offset
            j_count = 0
            for l in cmp_blk:
                if wrap_j_hit_add.lower() in l:
                    j_count += 1
            total = ord(name[i])+j_count
            if total > ord('z'):
                total -= 26
            char = chr(total)
            guesses.append(char)

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
    if correct:
        # We have it fully correct
        return guesses, False
    if equal_true_add.lower() in ''.join(last_block) and len(guesses) == len(name):
        # The return does a comparision with an &&, where the && lets us check it
        return guesses, False
    if len(guesses) < len(name):
        # We were able to reproduce it
        return guesses, False
    return guesses, True

def main():
    if len(sys.argv) != 2:
        print(f"This code expects a single arguments! arg1: /path/to/traces/folder")
    id = sys.argv[1]
    # Run pin
    filename = "~/isl/t2/trace.txt"
    runPin = f"cd /home/sgx/pin-3.11-97998-g7ecce2dac-gcc-linux-master/source/tools/SGXTrace && ../../../pin -t ./obj-intel64/SGXTrace.so -o {filename} -trace 1 -- ~/isl/t2/password_checker_2 magicaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaal"
    os.system(runPin)
    output = f"/home/sgx/isl/t2/output/oput_{id}"
    #print(f"Running on {path_folder} with {id} and output to {output}")
    guess, partial = parse_interesting(filename)
    guess_s = ''.join(guess)
    #print(f"Found {guess_s} with partial {partial}")
    out_s = f"{guess_s},{'partial' if partial else 'complete'}"
    #print(f"Wrote {out_s}")
    with open(output, "w") as out:
        out.writelines(out_s)

if __name__ == "__main__":
    main()