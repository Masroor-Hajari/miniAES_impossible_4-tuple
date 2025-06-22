# Implementation of miniAES block cipher

from GFexp2by4 import Xor, int2nib, nib2int, multiply2, multiply3
##################################SBox####################################
#miniAES SBOX function.
def SBox(B1):
    i = nib2int(B1)
    S = [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7]
    j = S[i]
    B2 = int2nib(j)
    return B2
##########################################################################

#################################InvSBox##################################
#miniAES inverse-SBOX function.
def InvSBox(B1):
    i = nib2int(B1)
    IS = [14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5]
    j = IS[i]
    B2 = int2nib(j)
    return B2
##########################################################################

###############################SubNibbles#################################
#miniAES SubNibbles operation.
def SubNibbles(X):
    Y = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    for i in range(0,2):
        for j in range(0,2):
            Y[i][j] = SBox(X[i][j])
    return Y
##########################################################################

##############################InvSubNibbles###############################
#miniAES inverse-SubNibbles operation.
def InvSubNibbles(X):
    Y = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    for i in range(0,2):
        for j in range(0,2):
            Y[i][j] = InvSBox(X[i][j])
    return Y
##########################################################################

################################ShiftRows#################################
#miniAES ShiftRows operation.
def ShiftRows(X):
    Y = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    Y[0][0] = X[0][0]
    Y[0][1] = X[0][1]
    Y[1][0] = X[1][1]
    Y[1][1] = X[1][0]
    return Y
##########################################################################

##############################oneMixColumn################################
#miniAES Mixing of one input column operation.
def oneMixColumn(X):
    Y = [[0,0,0,0],[0,0,0,0]]
    T0 = multiply3(X[0])
    T1 = multiply2(X[1])
    T2 = multiply2(X[0])
    T3 = multiply3(X[1])
    Y[0] = Xor(T0,T1)
    Y[1] = Xor(T2,T3)
    return Y
##########################################################################

###############################MixColumns#################################
#miniAES MixColumns operation.
def MixColumns(X):
    Y = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    T0 = multiply3(X[0][0])
    T1 = multiply2(X[1][0])
    T2 = multiply2(X[0][0])
    T3 = multiply3(X[1][0])
    T4 = multiply3(X[0][1])
    T5 = multiply2(X[1][1])
    T6 = multiply2(X[0][1])
    T7 = multiply3(X[1][1])
    Y[0][0] = Xor(T0,T1)
    Y[1][0] = Xor(T2,T3)
    Y[0][1] = Xor(T4,T5)
    Y[1][1] = Xor(T6,T7)
    return Y
##########################################################################

###############################AddRoundKey################################
#miniAES MixColumns operation.
def AddRoundKey(X,K):
    Y = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    for i in range(0,2):
        for j in range(0,2):
            Y[i][j] = Xor(X[i][j],K[i][j])
    return Y
##########################################################################

##############################RoundFunction###############################
#miniAES round funvtion.
def RoundFunc(X,K):
    Y = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    W = SubNibbles(X)
    W = ShiftRows(W)
    Z = MixColumns(W)
    Y = AddRoundKey(Z,K)
    return Y
##########################################################################

###############################KeySchedule################################
#miniAES one-round key schedule process.
def KeySchdl(MK,n):
    rcon = int2nib(n)
    RK = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    RK[0][0] = Xor(Xor(MK[0][0],SBox(MK[1][1])),rcon);
    RK[1][0] = Xor(MK[1][0],RK[0][0]);
    RK[0][1] = Xor(MK[0][1],RK[1][0]);
    RK[1][1] = Xor(MK[1][1],RK[0][1]);
    return RK
##########################################################################

#################################AES_Enc##################################
#miniAES one-round key schedule process.
def AES_Enc(P,MK,r):
    C = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    X = AddRoundKey(P,MK)
    RK = MK
    for i in range(1,r):
        RK = KeySchdl(RK,i)  
        X = RoundFunc(X,RK)
    X = SubNibbles(X)
    X = ShiftRows(X)
    RK = KeySchdl(RK,r) 
    C = AddRoundKey(X,RK)
    return C
##########################################################################
