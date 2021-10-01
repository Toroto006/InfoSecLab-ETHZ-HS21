import math
import random
import numpy as np
from fpylll import LLL
from fpylll import BKZ
from fpylll import IntegerMatrix
from fpylll import CVP
from fpylll import SVP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
    return _bit_list_to_int(list_k_LSB) # use same way as MSB_to_Padded_Int

def setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement a function that sets up a single instance for the hidden number problem (HNP)
    # The function is given a list of the L most significant bts of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return (t, u) computed as described in the lectures
    # In the case of EC-Schnorr, r may be set to h
    list_k_MSB = list(list_k_MSB)[:L] # shitty input as there might be k...
    assert len(list_k_MSB) == L
    if algorithm == "ecdsa":
        # ECDSA
        inv_s = mod_inv(s, q)
        t = r * inv_s % q
        if givenbits == "msbs":
            partial_u = MSB_to_Padded_Int(N, L, list_k_MSB)
            u = (partial_u - (h * inv_s)) % q
        else:
            a = LSB_to_Int(list_k_MSB)
            u = (a - (h * inv_s)) % q
            # to get 2**L away from e
            divisor = 2**L
            t = (t* mod_inv(divisor, q)) % q
            u = (u* mod_inv(divisor, q)) % q
    else:
        # ECschnorr
        t = h
        if givenbits == "msbs":
            partial_u = MSB_to_Padded_Int(N, L, list_k_MSB)
            u = (partial_u - s) % q
        else:
            a = LSB_to_Int(list_k_MSB)
            u = (a - s) % q
            # to get 2**L away from e
            divisor = 2**L
            t = (t* mod_inv(divisor, q)) % q
            u = (u* mod_inv(divisor, q)) % q
    if u > int(q/2)-1:
        u = u - q
    #assert -int(q/2) < u < int(q/2)
    # TODO maybe recheck why here q offset sometimes??
    return t, u
    

def setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement a function that sets up n = num_Samples many instances for the hidden number problem (HNP)
    # For each instance, the function is given a list the L most significant bits of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return a list of t values and a list of u values computed as described in the lectures
    # Hint: Use the function you implemented above to set up the t and u values for each instance
    # In the case of EC-Schnorr, list_r may be set to list_h
    ts = []
    us = []
    for list_k, h, r, s in zip(listoflists_k_MSB, list_h, list_r, list_s):
        t, u = setup_hnp_single_sample(N, L, list_k, h, r, s, q, givenbits, algorithm)
        ts.append(t)
        us.append(u)
    return ts, us

def hnp_to_cvp(N, L, num_Samples, list_t, list_u, q):
    # Implement a function that takes as input an instance of HNP and converts it into an instance of the closest vector problem (CVP)
    # The function is given as input a list of t values, a list of u values and the base point order q
    # The function should return the CVP basis matrix B (to be implemented as a nested list) and the CVP target vector u (to be implemented as a list)
    # NOTE: The basis matrix B and the CVP target vector u should be scaled appropriately. Refer lecture slides and lab sheet for more details 
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
    # Matrix to build: [[B_cvp , 0], [u_cvp, M]]
    # fp is short vector of above with: [f, M], where f = u_cvp - v
    # TODO Q6: --> M = "lamb_1/2" == (shortest non-zero vectors length)/2 of B_cvp?
    
    #power = num_Samples/(num_Samples+1) # because the num_Samples is the qs and then we have the 1
    #det_power_over_n = cvp_basis_B[0, 0]**power#+1
    #constant = ((num_Samples+1)/2*math.pi*math.e)**(1/2)
    #M = int(2/constant*det_power_over_n)**num_Samples # calculated M for when lamb_1/2 = M
    
    # M = 2^(3/(2 (1/(n + 1) - 1))) (e π)^(1/(2 (1/(n + 1) - 1))) ((2^(L + 1) q)^(-(n - 1)/(n + 1))/sqrt(n + 1))^(1/(1/(n + 1) - 1))
    # works for all other than for a few L = 8...
    #n = num_Samples + 1
    #constant = (2**(3/(2*((1/(n + 1) - 1)))))*((math.pi*math.e)**(1/(2*((1/(n + 1) - 1)))))
    #q = cvp_basis_B[0, 0] # but scaled with 2^(L + 1) 
    #q_part = (q**(-(n - 1)/(n + 1))/((n + 1)**(1/2)))**(1/(1/(n + 1) - 1))
    #M = int(constant * q_part)
    
    # last try - Works FINALLY!!
    q = cvp_basis_B[0, 0] # but scaled with 2^(L + 1) 
    power = num_Samples/(num_Samples+1) # because the num_Samples is the qs and then we have the 1
    M = int(q**power*(1/num_Samples+1)/math.sqrt(2*math.pi*math.e))

    B_svp = IntegerMatrix(cvp_basis_B)
    B_svp.resize(cvp_basis_B.nrows+1, cvp_basis_B.ncols+1)
    # Q7: how to scale M to preserve SVP correctness --> do not scale as q is already scaled in calculations
    last_row = cvp_list_u + [M]
    # set the last row
    for i in range(0, len(last_row)):
        B_svp[num_Samples+1,i] = last_row[i]
    #for r in interger_mat_to_list(B_svp):
    #    print(r)
    return B_svp

def solve_cvp(cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and solves it using in-built CVP-solver functions from the fpylll library
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should output the solution vector v (to be implemented as a list)
    # NOTE: The basis matrix B should be processed appropriately before being passes to the fpylll CVP-solver. See lab sheet for more details
    # Q4: some pre-processing? --> "closest_vector assumes that the input basis is LLL reduced" src:https://github.com/fplll/fpylll/issues/124
    # Q5: what to use? --> use LLL.reduction
    #print("starting reduction")
    LLL.reduction(cvp_basis_B)
    v = CVP.closest_vector(cvp_basis_B, cvp_list_u, method="fast")
    return list(v)

def solve_svp(svp_basis_B):
    # Implement a function that takes as input an instance of SVP and solves it using in-built SVP-solver functions from the fpylll library
    # The function is given as input the SVP basis matrix B
    # The function should output a list of candidate vectors that may contain x as a coefficient
    # NOTE: Recall from the lecture and also from the exercise session that for ECDSA cryptanalysis based on partial nonces, you might want
    #       your function to include in the list of candidate vectors the *second* shortest vector (or even a later one). 
    # If required, figure out how to get the in-built SVP-solver functions from the fpylll library to return the second (or later) shortest vector
    # Q8: Yes preprocessing makes it quicker --> the new SVP solver uses the following or run_lll?
    #svp_basis_B = BKZ.reduction(svp_basis_B, BKZ.EasyParam(max(svp_basis_B.nrows - 10, 2)))
    # args: ('B', 'method', 'flags', 'pruning', 'run_lll', 'max_aux_sols', 'method_', 'r', 'sol_coord', 'solution', 'pruning_', 'auxsol_coord', 'auxsol_dist', 'i', 'v', 'aux', 'j', 'aux_sol')
    LLL.reduction(svp_basis_B)
    #fps = SVP.shortest_vector(svp_basis_B, run_lll=True, method="proved", max_aux_sols=1)
    #fps = BKZ.reduction(svp_basis_B, BKZ.EasyParam(2))
    return list(svp_basis_B)


def recover_x_partial_nonce_CVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
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
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    svp_basis_B = cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u)
    list_of_f_List = solve_svp(svp_basis_B)
    # The function should recover the secret signing key x from the output of the SVP solver and return it
    # Q9: there should be a [ 0 .. q 0 ] somewhere? --> didn't find it yet
    # Q10: convinced the vector is usually the second shortest, use that
    f = list_of_f_List[1]
    if len(list(f))-2 != num_Samples:
        f = list_of_f_List[0]
    #v = list(map(lambda a, b: a - b, cvp_list_u, f))
    #print(list_of_f_List)
    i = len(f)-2
    # Q11: bc CVP is already scaled, what do you expect? --> similar to directly doing CVP we get x directly back
    x = (cvp_list_u[i]-f[i])%q
    #if not check_x(x, Q):
    #    print(f"Q: {Q}, N: {N}, L:{L} failed")
    #    print(list_of_f_List)
    return x

# testing code: do not modify

from module_1_ECDSA_Cryptanalysis_tests import run_tests

run_tests(recover_x_known_nonce,
    recover_x_repeated_nonce,
    recover_x_partial_nonce_CVP,
    recover_x_partial_nonce_SVP
)
