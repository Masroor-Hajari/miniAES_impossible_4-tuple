# Impossible 4-tuple cryptanalysis of miniAES
#Typical Variant
# I. First Phase
    #1. Partial Decryption
    #2. Data Collection
    
# II. Second Phase
    #1. Partial Decryption
    #2. Data Collection

import random   
from GFexp2by4 import Xor, int2nib, nib2int
from miniAES_Functions import InvSBox, oneMixColumn, AddRoundKey
from miniAES_Oracle import Generate, ctxReader

##############################DataCollector###############################
def DataCollector(StrVec,PtxStr,KeyStr,CtxStr,Round,Phase):
    MAT = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
    f = open(PtxStr,"w")
    f.close()
    for i in range(0,15):
        for j in range(0,16):
            with open(PtxStr,"a") as f:
                f.write(MAT[i]+MAT[j]+",")
    for i in range(0,15):
        with open(PtxStr,"a") as f:
            f.write(MAT[15]+MAT[i]+",")
    with open(PtxStr,"a") as f:
        f.write(MAT[15]+MAT[15])
    f.close()
    Generate(PtxStr,KeyStr,CtxStr,StrVec,Round,Phase)
##########################################################################  

if __name__ == "__main__":
#########################1st Phase Initialization#########################
    StrVec = [random.randint(0,15),random.randint(0,15)]
    PtxStr = "miniAES_Ptx.txt"
    KeyStr = "miniAES_Key.txt"
    CtxStr = "miniAES_Ctx.txt"
    Round = 5
    Phase = 1
    ctr = 0
    zeroNib = [0,0,0,0]
    X = [[[0] * 4 for i in range(4)] for j in range(784)]
    Y = [[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib]]
    Z = [[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib]]
    S = [[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib]]
    P = [[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib]]
    RecKey = [[zeroNib,zeroNib],[zeroNib,zeroNib]]
    KeyFlags = [True] * 256
    C0 = [[[0],[0]],[[0],[0]]]
    C1 = [[[0],[0]],[[0],[0]]]
    C2 = [[[0],[0]],[[0],[0]]]
    C3 = [[[0],[0]],[[0],[0]]]
##########################################################################

#######################1st Phase Partial Decryption#######################
    for i in range(0,8):
        for j in range(0,8):
            for l in range(i + 1,8):
                for m in range(j + 1,8):
                    Y[0][0] = int2nib(i)
                    Y[0][1] = int2nib(j)
                    Y[1][0] = int2nib(l)
                    Y[1][1] = int2nib(m)
                    Y[2][0] = int2nib(l)
                    Y[2][1] = int2nib(j)
                    Y[3][0] = int2nib(i)
                    Y[3][1] = int2nib(m)
                    for u in range(0,4):
                        Z[u] = oneMixColumn(Y[u])
                        for v in range(0,2):
                            X[ctr][u][v] = InvSBox(Z[u][v])
                    ctr += 1
##########################################################################

########################1st Phase Data Collection#########################
    DataCollector(StrVec,PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList = ctxReader(CtxStr)
    ctr = 0
    for i in range(0,8):
        for j in range(0,8):
            print("Phase1: ", (10000 * (j + 8 * i + 1) // 64) / 100, "% completed.")
            for l in range(i + 1,8):
                for m in range(j + 1,8):
                    S = X[ctr]
                    ctr += 1
                    for k0 in range(0,16):
                        nibK0 = int2nib(k0)
                        for k1 in range(0,16):
                            Index = 16 * k0 + k1
                            if KeyFlags[Index] == False:
                                continue
                            else:
                                nibK1 = int2nib(k1)
                                P[0][0] = Xor(S[0][0],nibK0)
                                P[1][0] = Xor(S[1][0],nibK0)
                                P[2][0] = Xor(S[2][0],nibK0)
                                P[3][0] = Xor(S[3][0],nibK0)
                                P[0][1] = Xor(S[0][1],nibK1)
                                P[1][1] = Xor(S[1][1],nibK1)
                                P[2][1] = Xor(S[2][1],nibK1)
                                P[3][1] = Xor(S[3][1],nibK1)
                                Num1 = nib2int(P[0][0])
                                Num2 = nib2int(P[0][1])
                                Index2 = 16 * Num1 + Num2
                                C0 = CtxList[Index2]
                                Num1 = nib2int(P[1][0])
                                Num2 = nib2int(P[1][1])
                                Index2 = 16 * Num1 + Num2
                                C1 = CtxList[Index2]
                                Num1 = nib2int(P[2][0])
                                Num2 = nib2int(P[2][1])
                                Index2 = 16 * Num1 + Num2
                                C2 = CtxList[Index2]
                                Num1 = nib2int(P[3][0])
                                Num2 = nib2int(P[3][1])
                                Index2 = 16 * Num1 + Num2
                                C3 = CtxList[Index2]
                                if (C0[0][0] == C1[0][0] and C0[1][1] == C1[1][1] and (C2[0][0] != C3[0][0] or C2[1][1] != C3[1][1])) or (C2[0][0] == C3[0][0] and C2[1][1] == C3[1][1] and (C0[0][0] != C1[0][0] or C0[1][1] != C1[1][1])) or (C0[0][1] == C1[0][1] and C0[1][0] == C1[1][0] and (C2[0][1] != C3[0][1] or C2[1][0] != C3[1][0])) or (C2[0][1] == C3[0][1] and C2[1][0] == C3[1][0] and (C0[0][1] != C1[0][1] or C0[1][0] != C1[1][0])):
                                    KeyFlags[Index] = False
    for i in range(0,16):
        for j in range(0,16):
            if KeyFlags[16 * i + j] == True:
                RecKey[0][0] = int2nib(i)
                RecKey[1][1] = int2nib(j)
                break
##########################################################################

#########################2nd Phase Initialization#########################
    StrVec = [random.randint(0,15),random.randint(0,15)]
    Phase = 2
    KeyFlags = [True] * 256
##########################################################################

#######################2nd Phase Partial Decryption#######################
    #The array X has already been created during the partial decryption step of the 1st phase. No action is needed for this phase.
##########################################################################

########################2nd Phase Data Collection#########################
    DataCollector(StrVec,PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList = ctxReader(CtxStr)
    ctr = 0
    for i in range(0,8):
        for j in range(0,8):
            print("Phase2: ", (10000 * (j + 8 * i + 1) // 64) / 100, "% completed.")
            for l in range(i + 1,8):
                for m in range(j + 1,8):
                    S = X[ctr]
                    ctr += 1
                    for k0 in range(0,16):
                        nibK0 = int2nib(k0)
                        for k1 in range(0,16):
                            Index = 16 * k0 + k1
                            if KeyFlags[Index] == False:
                                continue
                            else:
                                nibK1 = int2nib(k1)
                                P[0][0] = Xor(S[0][1],nibK0)
                                P[1][0] = Xor(S[1][1],nibK0)
                                P[2][0] = Xor(S[2][1],nibK0)
                                P[3][0] = Xor(S[3][1],nibK0)
                                P[0][1] = Xor(S[0][0],nibK1)
                                P[1][1] = Xor(S[1][0],nibK1)
                                P[2][1] = Xor(S[2][0],nibK1)
                                P[3][1] = Xor(S[3][0],nibK1)
                                Num1 = nib2int(P[0][0])
                                Num2 = nib2int(P[0][1])
                                Index2 = 16 * Num1 + Num2
                                C0 = CtxList[Index2]
                                Num1 = nib2int(P[1][0])
                                Num2 = nib2int(P[1][1])
                                Index2 = 16 * Num1 + Num2
                                C1 = CtxList[Index2]
                                Num1 = nib2int(P[2][0])
                                Num2 = nib2int(P[2][1])
                                Index2 = 16 * Num1 + Num2
                                C2 = CtxList[Index2]
                                Num1 = nib2int(P[3][0])
                                Num2 = nib2int(P[3][1])
                                Index2 = 16 * Num1 + Num2
                                C3 = CtxList[Index2]
                                if (C0[0][0] == C1[0][0] and C0[1][1] == C1[1][1] and (C2[0][0] != C3[0][0] or C2[1][1] != C3[1][1])) or (C2[0][0] == C3[0][0] and C2[1][1] == C3[1][1] and (C0[0][0] != C1[0][0] or C0[1][1] != C1[1][1])) or (C0[0][1] == C1[0][1] and C0[1][0] == C1[1][0] and (C2[0][1] != C3[0][1] or C2[1][0] != C3[1][0])) or (C2[0][1] == C3[0][1] and C2[1][0] == C3[1][0] and (C0[0][1] != C1[0][1] or C0[1][0] != C1[1][0])):
                                    KeyFlags[Index] = False
    for i in range(0,16):
        for j in range(0,16):
            if KeyFlags[16 * i + j] == True:
                RecKey[1][0] = int2nib(i)
                RecKey[0][1] = int2nib(j)
                break
##########################################################################

###############################Key Recovery###############################
print("Recovered master key:")
print("\tBlock representation: ", [RecKey])
print("\tStream representation: ", end = "")
for i in range(0,2):
    for j in range(0,2):
        for k in range(0,4):
            if k==3 and j==1 and i==1:
                print(RecKey[j][i][k])
            else:
                print(RecKey[j][i][k], end = "")
print("\tHexadecimal representation: ", end = "")
for i in range(0,2):
    for j in range(0,2):
        n = nib2int(RecKey[j][i])
        if n < 10:
            Str = chr(48 + n)
            if j==1 and i==1:
                print(Str)
            else:
                print(Str, end = "")
        else:
            Str = chr(87 + n)
            if j==1 and i==1:
                print(Str)
            else:
                print(Str, end = "")
##########################################################################
