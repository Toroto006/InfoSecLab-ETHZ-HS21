import unittest
import filecmp
from tqdm import tqdm
import re

num_Experiments = 50
partial_nonce_instances = [
    # (N, L, num_Samples)
    #(256, 128, 5),
    #(256, 32, 10),
    #(256, 16, 20),
    (256, 8, 60),
]

class TestCryptanalysis(unittest.TestCase):

    def test_known_nonce_attack(self):
        with self.subTest(f"Known nonce attack"):
            self.assertTrue(filecmp.cmp(
                'unit_test_known_nonce_outputs_temp.txt', 'unit_test_known_nonce_outputs.txt'))

    def test_repeated_nonce_attack(self):
        with self.subTest(f"Repeated nonce attack"):
            self.assertTrue(filecmp.cmp(
                'unit_test_repeated_nonce_outputs_temp.txt', 'unit_test_repeated_nonce_outputs.txt'))

    def test_partial_nonce_attack_CVP(self):
        for instance in partial_nonce_instances:
            N, L, num_Samples = instance
            for givenbits in ["msbs", "lsbs"]:
                for algorithm in ["ecdsa", "ecschnorr"]:
                    fn1 = f'unit_test_partial_nonce{"_lsbs" if givenbits == "lsbs" else ""}_outputs_CVP_{N}_{L}_{num_Samples}{"_ecschnorr" if algorithm == "ecschnorr" else ""}.txt'
                    fn2 = f'unit_test_partial_nonce{"_lsbs" if givenbits == "lsbs" else ""}_outputs_{N}_{L}_{num_Samples}{"_ecschnorr" if algorithm == "ecschnorr" else ""}.txt'
                    with self.subTest(f"CVP, givenbits: {givenbits}, algorithm: {algorithm}, L: {L}"):
                        # if not filecmp.cmp(fn1, fn2):
                        #     print(f"Fail at CVP test givenbits {givenbits} algorithm {algorithm}")
                        self.assertTrue(filecmp.cmp(fn1, fn2))

    def test_partial_nonce_attack_SVP(self):
        for instance in partial_nonce_instances:
            N, L, num_Samples = instance
            for givenbits in ["msbs", "lsbs"]:
                for algorithm in ["ecdsa", "ecschnorr"]:
                    fn1 = f'unit_test_partial_nonce{"_lsbs" if givenbits == "lsbs" else ""}_outputs_SVP_{N}_{L}_{num_Samples}{"_ecschnorr" if algorithm == "ecschnorr" else ""}.txt'
                    fn2 = f'unit_test_partial_nonce{"_lsbs" if givenbits == "lsbs" else ""}_outputs_{N}_{L}_{num_Samples}{"_ecschnorr" if algorithm == "ecschnorr" else ""}.txt'
                    with self.subTest(f"SVP, givenbits: {givenbits}, algorithm: {algorithm}, L: {L}"):
                        # if not filecmp.cmp(fn1, fn2):
                        #     print(f"Fail at SVP test givenbits {givenbits} algorithm {algorithm}")
                        self.assertTrue(filecmp.cmp(fn1, fn2))

    def test_hnp_single_sample(self):
        fn1 = f'testvectors_hnp_single_sample_256_128_temp.txt'
        fn2 = f'testvectors_hnp_single_sample_256_128_output.txt'
        self.assertTrue(filecmp.cmp(fn1, fn2))

    def testvectors_hnp_all_samples_256_128(self):
        fn1 = f'testvectors_hnp_all_samples_256_128_100_output.txt'
        fn2 = f'testvectors_hnp_all_samples_256_128_100_temp.txt'
        self.assertTrue(filecmp.cmp(fn1, fn2))

# Parameters for NIST P-256:
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def generate_outputs(recover_x_known_nonce,
    recover_x_repeated_nonce,
    recover_x_partial_nonce_CVP,
    recover_x_partial_nonce_SVP
    ):

    # Unit testing of the "known nonce" attack on ECDSA
    try:
        known_nonce_out = []
        print("Solving known and repeated nonces")
        with open('unit_test_known_nonce_inputs.txt', 'r') as filehandle:
            while True:
                known_nonce_inp = filehandle.readline().split()
                if len(known_nonce_inp) == 0:
                    # end of file reached
                    break
                k = int(known_nonce_inp[0])
                h = int(known_nonce_inp[1])
                r = int(known_nonce_inp[2])
                s = int(known_nonce_inp[3])
                x = recover_x_known_nonce(k, h, r, s, q)
                known_nonce_out.append(x)

        with open('unit_test_known_nonce_outputs_temp.txt', 'w') as filehandle:
            for x in known_nonce_out:
                filehandle.write('%d\n' % x)
    except NotImplementedError:
        pass

    # Unit testing of the "repeated nonces" attack on ECDSA
    try:
        repeated_nonce_out = []
        with open('unit_test_repeated_nonce_inputs.txt', 'r') as filehandle:
            while True:
                repeated_nonce_inp = filehandle.readline().split()
                if len(repeated_nonce_inp) == 0:
                    # end of file reached
                    break
                h_1 = int(repeated_nonce_inp[0])
                r_1 = int(repeated_nonce_inp[1])
                s_1 = int(repeated_nonce_inp[2])
                h_2 = int(repeated_nonce_inp[3])
                r_2 = int(repeated_nonce_inp[4])
                s_2 = int(repeated_nonce_inp[5])
                x = recover_x_repeated_nonce(h_1, r_1, s_1, h_2, r_2, s_2, q)
                repeated_nonce_out.append(x)

        with open('unit_test_repeated_nonce_outputs_temp.txt', 'w') as filehandle:
            for x in repeated_nonce_out:
                filehandle.write('%d\n' % x)
    except NotImplementedError:
        pass

    # Unit testing phase-1 of the "partial nonce" attack on ECDSA using CVP and SVP for parameters mentioned below
    for givenbits in ["msbs", "lsbs"]:
        for algorithm in ["ecdsa", "ecschnorr"]:
            for instance in partial_nonce_instances:
                N, L, num_Samples = instance

                list_x_CVP = []
                list_x_SVP = []

                print(f"Solving {givenbits} order bits {algorithm} instance N {N} L {L} with {num_Samples} samples")

                # load and solve challenges
                with open(f'unit_test_partial_nonce{"_lsbs" if givenbits == "lsbs" else ""}_inputs_{N}_{L}_{num_Samples}{"_ecschnorr" if algorithm == "ecschnorr" else ""}.txt', 'r') as filehandle:
                    for exp in tqdm(range(num_Experiments)):
                        listoflists_k_leak = []
                        list_h = []
                        list_r = []
                        list_s = []
                        Q_x = int(filehandle.readline())
                        Q_y = int(filehandle.readline())
                        Q = (Q_x, Q_y)
                        for samp in range(num_Samples):
                            line_space = filehandle.readline()
                            line_k_leak = filehandle.readline().split()
                            list_k_leak = []
                            for bit in line_k_leak:
                                list_k_leak.append(int(bit))
                            listoflists_k_leak.append(list_k_leak)
                            line_space = filehandle.readline()
                            line_h_r_s = filehandle.readline().split()
                            # print(line_h_r_s)
                            list_h.append(int(line_h_r_s[0]))
                            list_r.append(int(line_h_r_s[1]))
                            list_s.append(int(line_h_r_s[2]))
                        x_recovered_cvp = recover_x_partial_nonce_CVP(Q, N, L, num_Samples, listoflists_k_leak, list_h, list_r, list_s, q, givenbits=givenbits, algorithm=algorithm)
                        x_recovered_svp = recover_x_partial_nonce_SVP(Q, N, L, num_Samples, listoflists_k_leak, list_h, list_r, list_s, q, givenbits=givenbits, algorithm=algorithm)
                        list_x_CVP.append(x_recovered_cvp)
                        list_x_SVP.append(x_recovered_svp)

                # save results
                with open(f'unit_test_partial_nonce{"_lsbs" if givenbits == "lsbs" else ""}_outputs_CVP_{N}_{L}_{num_Samples}{"_ecschnorr" if algorithm == "ecschnorr" else ""}.txt', 'w') as filehandle:
                    for x in list_x_CVP:
                        filehandle.write('\n%d\n' % (x))
                with open(f'unit_test_partial_nonce{"_lsbs" if givenbits == "lsbs" else ""}_outputs_SVP_{N}_{L}_{num_Samples}{"_ecschnorr" if algorithm == "ecschnorr" else ""}.txt', 'w') as filehandle:
                    for x in list_x_SVP:
                        filehandle.write('\n%d\n' % (x))

def generate_my_outputs(setup_hnp_single_sample, setup_hnp_all_samples):
    # Unit testing of the "single sample hnp" attack on ECDSA
    if setup_hnp_all_samples is None:
        return
    print("Solving HNP tests")
    try:
        single_test_regex = r"list_k_MSB\s*=\s([1,0,\ ]*)\s\nh\s=\s(\d*)\s\nr\s=\s(\d*)\s\ns\s=\s(\d*)\s\nt\s=\s(\d*)\s\nu\s=\s([\d-]*)\s\n"
        with open('testvectors_hnp_single_sample_256_128.txt', 'r') as filehandle:
            content = filehandle.read()
        with open('testvectors_hnp_single_sample_256_128_temp.txt', 'w') as fileout:
            matches = re.finditer(single_test_regex, content, re.MULTILINE)
            for match in matches:
                #print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
                N, L = (256, 128)
                list_k_MSB = map(int, match.group(1).strip().split(' '))
                h = int(match.group(2))
                r = int(match.group(3))
                s = int(match.group(4))
                t = int(match.group(5))
                u = int(match.group(6))
                t_calculated, u_calculated = setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q)
                fileout.write(f"diff ts: {t-t_calculated}\tdiff us:{(u-u_calculated) % q}\n")
    except NotImplementedError:
        pass

    # Unit testing of the "single sample hnp" attack on ECDSA
    try:
        N_SAMPLES = 5
        all_samples_regex = r"listoflists_k_MSB:\n([1,0,\ \n]*)\nlist_h:\n([\d\s]*)\nlist_r:\n([\d\s]*)\nlist_s:\n([\d\s]*)\nlist_t:\n([\d\s]*)\nlist_u:\n([-\d\s]*)"
        with open('testvectors_hnp_all_samples_256_128_100.txt', 'r') as filehandle:
            content = filehandle.read()
        with open('testvectors_hnp_all_samples_256_128_100_temp.txt', 'w') as fileout:
            matches = re.finditer(all_samples_regex, content, re.MULTILINE)
            for match in matches:
                #print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
                N, L = (256, 128)
                listoflists_k_MSB = map(lambda x: list(map(int, x.strip().split(' '))), match.group(1).strip().split('\n'))
                h = map(int, match.group(2).strip().split(' '))
                r = map(int, match.group(3).strip().split(' '))
                s = map(int, match.group(4).strip().split(' '))
                t_list = map(int, match.group(5).strip().split(' '))
                u_list = map(int, match.group(6).strip().split(' '))
                ts, us = setup_hnp_all_samples(N, L, N_SAMPLES, listoflists_k_MSB, h, r, s, q)
                for t, u, t_calculated, u_calculated in zip(t_list, u_list, ts, us):
                    fileout.write(f"diff ts: {t-t_calculated}\tdiff us:{(u-u_calculated) % q}\n")
    except NotImplementedError:
        pass
    
    print("Done with the HNP calculations")

def run_tests(recover_x_known_nonce,
    recover_x_repeated_nonce,
    recover_x_partial_nonce_CVP,
    recover_x_partial_nonce_SVP,
    setup_hnp_single_sample=None,
    setup_hnp_all_samples=None
    ):

    # original generate outputs not failing with unimplemented
    generate_outputs(recover_x_known_nonce,
        recover_x_repeated_nonce,
        recover_x_partial_nonce_CVP,
        recover_x_partial_nonce_SVP
    )

    # my ouputs
    generate_my_outputs(setup_hnp_single_sample, setup_hnp_all_samples)

    suite = unittest.TestSuite()
    suite.addTest(TestCryptanalysis('test_known_nonce_attack'))
    suite.addTest(TestCryptanalysis('test_repeated_nonce_attack'))
    #suite.addTest(TestCryptanalysis('test_hnp_single_sample'))
    #suite.addTest(TestCryptanalysis('testvectors_hnp_all_samples_256_128'))
    suite.addTest(TestCryptanalysis('test_partial_nonce_attack_CVP'))
    suite.addTest(TestCryptanalysis('test_partial_nonce_attack_SVP'))
    runner = unittest.TextTestRunner()
    runner.run(suite)
