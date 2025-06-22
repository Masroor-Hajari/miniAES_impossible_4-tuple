# Galois Field 2^4: P(X) = X^4 + X + 1

###################################Xor####################################
#Xor operation on 4-bit nibbles.
def Xor(B1,B2):
    B3 = [0,0,0,0]
    for i in range(0,4):
        B3[i] = (B1[i] + B2[i]) % 2
    return B3
##########################################################################

#################################int2nib##################################
#Extract the corresponding nibble form of integer numbers between 0 and 15.
def int2nib(I):
    B = [0,0,0,0]
    Temp = I
    for i in range(0,4):
        B[3-i] = Temp % 2
        Temp = (Temp - B[3-i]) // 2
    return B
##########################################################################

#################################nib2int##################################
#Extract the corresponding integer number from the input nibble.
def nib2int(B):
    I = 8 * B[0] + 4 * B[1] + 2 * B[2] + B[3]
    return I
##########################################################################

################################multiply2#################################
#multiplying the input nibble into 0x2 (0010).
def multiply2(B):
    C=[0,0,0,0]
    for i in range(1,4):
        C[i - 1] = B[i]
    if B[0] == 1:
        C[2] = 1 - C[2]
        C[3] = 1 - C[3]
    return C
##########################################################################
        
################################multiply3#################################
#multiplying the input nibble into 0x3 (0011).
def multiply3(B):
    C = multiply2(B)
    C = Xor(C,B)
    return C
##########################################################################
