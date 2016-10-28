import math

seed = 1000

def pmms_rand(N):
    global seed
    seed = (7**5 * seed) % (2**31 - 1)
    return math.floor(N*seed/(2**31 - 1))
    


# Initialize the left side of the parity check matrix.
def left_matrix_init(k, n, N1):
    # Initialize a list of all possible choices in order to
    # guarantee a homogeneous "1" distribution */
    u = [h % (n-k) for h in range(N1*k)]

    # empty parity check matrix (left side)
    M = [list() for _ in range(n-k)]

    # Initialize the matrix with N1 "1s" per column, homogeneously
    t = 0
    for j in range(k): # for each source symbol column
        for h in range(N1): # add N1 "1s"
            # check that valid available choices remain
            i = t
            while i < N1 * k and j in M[u[i]]:
                i = i + 1
            if i < N1 * k:
                # choose one index within the list of possible choices
                while True:
                    i = t + pmms_rand(N1*k - t)
                    if j not in M[u[i]]:
                        break
                M[u[i]].append(j)
                # replace with u[t] which has never been chosen
                u[i] = u[t]
                t = t + 1
            else:
                # no choice left, choose one randomly
                while True:
                    i = pmms_rand(n - k)
                    if j not in M[i]:
                        break
                M[i].append(j)

    # Add extra bits to avoid rows with less than two "1s".
    # This is needed when the code rate is smaller than 2/(2+N1) */
    for i in range(n-k): # for each row
        if len(M[i]) == 0:
            j = pmms_rand(k)
            M[i].append(j)
        if len(M[i]) == 1:
            while True:
                j = pmms_rand(k)
                if j not in M[i]:
                    break
            M[i].append(j)
        
    return M
