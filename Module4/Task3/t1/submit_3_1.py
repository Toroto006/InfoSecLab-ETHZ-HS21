import sys
import os
import glob

# No ASLR so these are fix
input_le_add =          "4011D0"
input_done_add =        "4011D4"
comparision_true_add =  "401211"
end_loop_add =          "401288"
distance_add_add =      "40126F"
wrap_j_hit_add =        "40127E"
correct_add =           "40140C"
wrong_add =             "401413"

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
    print(f"Doing {filename}")
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
    # In the start we see if the test password is too long??? Not working bc cmovle on cmp
    #geuss_le = input_le_add.lower() in ''.join(start)
    #print(f"{filename} had {'<=' if geuss_le else '>'} characters")

    # These are the comparision blocks
    comp_blocks = blocking_on(comp, end_loop_add)
    # prepare guess string
    name = os.path.basename(filename)
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

    return guesses

def test(path_folder):
    for filename in glob.glob(os.path.join(path_folder, '*.txt')):
        guesses = parse_interesting(filename)
        print(guesses)
        #exit()

def main():
    if len(sys.argv) != 3:
        print(f"This code expects two arguments! arg1: /path/to/traces/folder arg2: id")
    path_folder = sys.argv[1]
    id = sys.argv[2]
    output = f"output/oput_{id}"
    print(f"Running on {path_folder} with {id} and output to {output}")
    test(path_folder)

if __name__ == "__main__":
    main()