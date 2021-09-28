import math
import random
from fpylll import LLL
from fpylll import BKZ
from fpylll import IntegerMatrix
from fpylll import CVP
from fpylll import SVP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import numpy as np

# Euclidean algorithm for gcd computation
def egcd(a, b):
    # Implement the Euclidean algorithm for gcd computation
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

# Modular inversion computation
def mod_inv(a, p):
    # Implement a function to compute the inverse of a modulo p
    # Hint: Use the gcd algorithm implemented above
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p

def check_x(x, Q):
    """ Given a guess for the secret key x and a public key Q = [x]P,
        checks if the guess is correct.

        :params x:  secret key, as an int
        :params Q:  public key, as a tuple of two ints (Q_x, Q_y)
    """
    x = int(x)
    if x <= 0:
        return False
    Q_x, Q_y = Q
    sk = ec.derive_private_key(x, ec.SECP256R1())
    pk = sk.public_key()
    xP = pk.public_numbers()
    return xP.x == Q_x and xP.y == Q_y

def recover_x_known_nonce(k, h, r, s, q):
    # Implement the "known nonce" cryptanalytic attack on ECDSA
    # The function is given the nonce k, (h, r, s) and the base point order q
    # The function should compute and return the secret signing key x
    return (mod_inv(r, q)*(k*s - h)) % q

def recover_x_repeated_nonce(h_1, r_1, s_1, h_2, r_2, s_2, q):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA
    # The function is given the (hashed-message, signature) pairs (h_1, r_1, s_1) and (h_2, r_2, s_2) generated using the same nonce
    # The function should compute and return the secret signing key x
    l = h_1*s_2 - h_2*s_1
    r = r_2*s_1 - r_1*s_2
    return (l*mod_inv(r, q)) % q

def _bit_list_to_int(bits):
    return int("0b"+''.join(map(str, bits)), 2) # convert list of bits to 0bxxx and convert to int

def MSB_to_Padded_Int(N, L, list_k_MSB):
    # Implement a function that does the following: 
    # Let a is the integer represented by the L most significant bits of the nonce k 
    # The function should return a.2^{N - L} + 2^{N -L -1}
    # calculate a from list_k_MS
    a = _bit_list_to_int(list_k_MSB)
    # return actual value partial u
    return a * 2**(N-L) + 2**(N-L-1)

def LSB_to_Int(list_k_LSB):
    # Implement a function that does the following: 
    # Let a is the integer represented by the L least significant bits of the nonce k 
    # The function should return a
    list_k_LSB.reverse() # reverse to get MSB in the front
    return _bit_list_to_int(list_k_LSB) # use same way as MSB_to_Padded_Int

def setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement a function that sets up a single instance for the hidden number problem (HNP)
    # The function is given a list of the L most significant bts of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return (t, u) computed as described in the lectures
    # In the case of EC-Schnorr, r may be set to h
    if algorithm == "ecdsa":
        # ECDSA
        inv_s = mod_inv(s, q)
        t = r * inv_s % q
        if givenbits == "msbs":
            partial_u = MSB_to_Padded_Int(N, L, list_k_MSB)
            u = (partial_u - (h * inv_s)) % q
            if u > int(q/2)-1:
                u = u - q
            #assert -int(q/2) < u < int(q/2)
            # TODO maybe recheck why here q offset sometimes??
        else:
            raise NotImplementedError()
            u = 0
    else:
        # ECschnorr
        raise NotImplementedError()
    return t, u
    

def setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement a function that sets up n = num_Samples many instances for the hidden number problem (HNP)
    # For each instance, the function is given a list the L most significant bits of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return a list of t values and a list of u values computed as described in the lectures
    # Hint: Use the function you implemented above to set up the t and u values for each instance
    # In the case of EC-Schnorr, list_r may be set to list_h
    ts = []
    us = []
    if algorithm == "ecdsa":
        # ECDSA
        if givenbits == "msbs":
            for list_k, h, r, s in zip(listoflists_k_MSB, list_h, list_r, list_s):
                t, u = setup_hnp_single_sample(N, L, list_k, h, r, s, q, givenbits, algorithm)
                ts.append(t)
                us.append(u)
        else:
            # lsbs
            raise NotImplementedError()
    else:
        # ECschnorr
        raise NotImplementedError()
    return ts, us

def hnp_to_cvp(N, L, num_Samples, list_t, list_u, q):
    # Implement a function that takes as input an instance of HNP and converts it into an instance of the closest vector problem (CVP)
    # The function is given as input a list of t values, a list of u values and the base point order q
    # The function should return the CVP basis matrix B (to be implemented as a nested list) and the CVP target vector u (to be implemented as a list)
    # NOTE: The basis matrix B and the CVP target vector u should be scaled appropriately. Refer lecture slides and lab sheet for more details 
    #for t in list_t + list_u: # test for integral parts...
    #    assert type(t) == int
    # Create B
    scalar = 2**(L+1)
    # TODO scaler appropriate ??
    B_cvp = np.diag([q*scalar]*(num_Samples+1)) # first create the diag q matrix
    one_over = int(1/2**(L+1)*scalar)           # calculate the lower right element
    scaled_ts = list(map(lambda x: x*scalar, list_t)) # scale the ts
    last_row = np.array(scaled_ts+[one_over])      # create last row with ts and lower right element
    B_cvp[num_Samples] = last_row               # Set the last row of the B matrix
    #print(f"one over: {B_cvp}")
    # Create u
    scaled_us = list(map(lambda x: x*scalar, list_u)) # scale the us
    u_cvp = np.array(scaled_us+[0])                # lets go over np to do changes later
    # Convert to fpylll format
    # maybe make merge request for correct error message https://github.com/fplll/fpylll/blob/1a99a15c6eebf61240a3b2c15ce9bde0ad470d13/src/fpylll/fplll/integer_matrix.pyx#L397
    converted_B_cvp = IntegerMatrix.from_matrix(B_cvp.tolist())
    converted_u_cvp = u_cvp.tolist()
    return converted_B_cvp, converted_u_cvp
    # TODO Q1: x - q returned? --> Maybe centering u does not make this likely?
    # Q2: fpylll can handle non integral? --> No, conversion just silently crashes...
    # TODO Q3: how to transform it? --> No clue, maybe just * scalar?

def cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and converts it into an instance of the shortest vector problem (SVP)
    # Your function should use the Kannan embedding technique in the lecture slides
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should use the Kannan embedding technique to output the corresponding SVP basis matrix B' of apropriate dimensions.
    # The SVP basis matrix B' should again be implemented as a nested list
    raise NotImplementedError()


def solve_cvp(cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and solves it using in-built CVP-solver functions from the fpylll library
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should output the solution vector v (to be implemented as a list)
    # NOTE: The basis matrix B should be processed appropriately before being passes to the fpylll CVP-solver. See lab sheet for more details
    # Q4: some pre-processing? --> "closest_vector assumes that the input basis is LLL reduced" src:https://github.com/fplll/fpylll/issues/124
    # Q5: what to use? --> use LLL.reduce
    #print("starting reduction")
    LLL.reduction(cvp_basis_B)
    if len(cvp_basis_B[0]) > 21:
        print("starting closest_vector")
    v = CVP.closest_vector(cvp_basis_B, cvp_list_u, method="fast")
    return list(v)

def solve_svp(svp_basis_B):
    # Implement a function that takes as input an instance of SVP and solves it using in-built SVP-solver functions from the fpylll library
    # The function is given as input the SVP basis matrix B
    # The function should output a list of candidate vectors that may contain x as a coefficient
    # NOTE: Recall from the lecture and also from the exercise session that for ECDSA cryptanalysis based on partial nonces, you might want
    #       your function to include in the list of candidate vectors the *second* shortest vector (or even a later one). 
    # If required, figure out how to get the in-built SVP-solver functions from the fpylll library to return the second (or later) shortest vector
    # max_aux_sols=0
    raise NotImplementedError()


def recover_x_partial_nonce_CVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    v_List = solve_cvp(cvp_basis_B, cvp_list_u)
    # The function should recover the secret signing key x from the output of the CVP solver and return it
    # TODO is correct?
    # as we scaled to have x lower right element, return that x?
    x = v_List[len(v_List)-1]%q
    #print(f"in N:{N} with L:{L} and {num_Samples} samples we have {check_x(x, Q)}") # --> TRUE up to 20 samples???
    return x

def recover_x_partial_nonce_SVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    svp_basis_B = cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u)
    list_of_f_List = solve_svp(svp_basis_B)
    # The function should recover the secret signing key x from the output of the SVP solver and return it
    raise NotImplementedError()

# testing code: do not modify

from module_1_ECDSA_Cryptanalysis_tests import run_tests

run_tests(recover_x_known_nonce,
    recover_x_repeated_nonce,
    recover_x_partial_nonce_CVP,
    recover_x_partial_nonce_SVP,
    setup_hnp_single_sample,
    setup_hnp_all_samples
)
