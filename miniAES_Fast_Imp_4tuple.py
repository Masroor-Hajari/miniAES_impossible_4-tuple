# Impossible 4-tuple cryptanalysis applied to miniAES
# Fast Variant
# I. First Phase
    #1. Precomputation
    #2. Data Collection
    #3. 4-tuple Extraction
    
# II. Second Phase
    #1. Precomputation
    #2. Data Collection
    #3. 4-tuple Extraction

import random   
from GFexp2by4 import Xor, int2nib, nib2int
from miniAES_Functions import InvSBox, oneMixColumn, AddRoundKey
from miniAES_Oracle import Generate, ctxReader, str2num

##############################DataCollector###############################
def DataCollector(StrVec,PtxStr,KeyStr,CtxStr,Round,Phase):
    MAT = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
    f = open(PtxStr,"w")
    f.close()
    for i in range(0,15):
        for j in range(0,16):
            with open(PtxStr,"a") as f:
                f.write(MAT[i] + MAT[j]+",")
    for i in range(0,15):
        with open(PtxStr,"a") as f:
            f.write(MAT[15]+MAT[i]+",")
    with open(PtxStr,"a") as f:
        f.write(MAT[15] + MAT[15])
    f.close()
    Generate(PtxStr,KeyStr,CtxStr,StrVec,Round,Phase)
##########################################################################  

###############################Precompute#################################
def Precompute(DataStr,N):
    # N is the number of required words per nibble (0<N<17)
    MAT = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
    zeroNib = [0,0,0,0]
    Y = [zeroNib,zeroNib]
    Z = [zeroNib,zeroNib]
    X = zeroNib
    f = open(DataStr,"w")
    f.close()
    for i in range(0,N):
        for j in range(0,N):
            Y[0] = int2nib(i)
            Y[1] = int2nib(j)
            Z = oneMixColumn(Y)
            for l in range(0,2):
                X = InvSBox(Z[l])
                I = nib2int(X)
                if l == 0 or (i == N - 1 and j == N - 1):
                    with open(DataStr,"a") as f:
                        f.write(MAT[I])
                else: 
                    with open(DataStr,"a") as f:
                        f.write(MAT[I] + ",")
    f.close()
##########################################################################

###############################DataReader#################################
def dataReader(Name):
    f = open(Name)
    Str = f.read()
    f.close()
    N = len(Str)
    M = (N + 1) // 3
    ctr = 0
    Arr = [[0] * 2 for i in range(M)]
    for i in range(0,N):
        if i % 3 == 2:
            ctr += 1
            continue
        else:
            Arr[ctr][i % 3] = str2num(Str[i])
    return Arr
##########################################################################

if __name__ == "__main__":
#########################1st Phase Initialization#########################
    StrVecCore = [random.randint(0,15),random.randint(0,15)]
    StrVecMask = [0,random.randint(1,5),random.randint(6,10),random.randint(11,15)]
    StrVec = [[0,0],[0,0],[0,0],[0,0]]
    StrVec[0] = StrVecCore
    for i in range (0,4):
        for j in range(0,2):
            StrVec[i][0] = (StrVecCore[0] + StrVecMask[i]) % 16
            StrVec[i][1] = StrVecCore[1] 
    DataStr = "miniAES_Precomp.txt"
    PtxStr = "miniAES_Ptx.txt"
    KeyStr = "miniAES_Key.txt"
    CtxStr = "miniAES_Ctx.txt"
    Round = 5
    Phase = 1
    zeroNib = [0,0,0,0]
    Y = [[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib]]
    Z = [[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib]]
    X = [[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib]]
    P = [[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib],[zeroNib,zeroNib]]
    RecKey = [[zeroNib,zeroNib],[zeroNib,zeroNib]]
    impFlag = False
    recFlag = False
    C0 = [[[0],[0]],[[0],[0]]]
    C1 = [[[0],[0]],[[0],[0]]]
    C2 = [[[0],[0]],[[0],[0]]]
    C3 = [[[0],[0]],[[0],[0]]]
##########################################################################

#########################1st Phase Precomputation#########################
    Precompute(DataStr,6)
##########################################################################
   
########################1st Phase Data Collection#########################
    DataCollector(StrVec[0],PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList0 = ctxReader(CtxStr)
    DataCollector(StrVec[1],PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList1 = ctxReader(CtxStr)
    DataCollector(StrVec[2],PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList2 = ctxReader(CtxStr)
    DataCollector(StrVec[3],PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList3 = ctxReader(CtxStr)
    CtxBook = [CtxList0, CtxList1, CtxList2, CtxList3]
    Words = dataReader(DataStr)
    for k0 in range(0,16):
        nibK0 = int2nib(k0)
        for k1 in range(0,16):
            nibK1 = int2nib(k1)
            Index = 16 * k0 + k1
            print("Phase1: ", (10000 * Index // 256) / 100, "% completed.")
##########################################################################

#######################1st Phase 4-tuple extraction#######################
            for i in range(0,6):
                for j in range(0,6):
                    IndexQuad0 = 6 * i + j
                    X[0][0] = int2nib(Words[IndexQuad0][0])
                    X[0][1] = int2nib(Words[IndexQuad0][1])
                    for l in range(i + 1,6):
                        IndexQuad2 = 6 * l + j
                        X[2][0] = int2nib(Words[IndexQuad2][0])
                        X[2][1] = int2nib(Words[IndexQuad2][1])
                        for m in range(j + 1,6):
                            IndexQuad1 = 6 * l + m
                            IndexQuad3 = 6 * i + m
                            X[1][0] = int2nib(Words[IndexQuad1][0])
                            X[1][1] = int2nib(Words[IndexQuad1][1])
                            X[3][0] = int2nib(Words[IndexQuad3][0])
                            X[3][1] = int2nib(Words[IndexQuad3][1])
                            P[0][0] = Xor(X[0][0],nibK0)
                            P[1][0] = Xor(X[1][0],nibK0)
                            P[2][0] = Xor(X[2][0],nibK0)
                            P[3][0] = Xor(X[3][0],nibK0)
                            P[0][1] = Xor(X[0][1],nibK1)
                            P[1][1] = Xor(X[1][1],nibK1)
                            P[2][1] = Xor(X[2][1],nibK1)
                            P[3][1] = Xor(X[3][1],nibK1)
                            for St in range(0,4):
                                Num1 = nib2int(P[0][0])
                                Num2 = nib2int(P[0][1])
                                CtxList = CtxBook[St]
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
                                    impFlag = True
                                    break
                            if impFlag == True:
                                break
                        if impFlag == True:
                            break
                    if impFlag == True:
                        break
                if impFlag == True:
                    break
            if impFlag == False:
                RecKey[0][0] = int2nib(k0)
                RecKey[1][1] = int2nib(k1)
                recFlag = True
                print("Phase1: ", 100.0, "% completed.")
                break
            else:
                impFlag = False
        if recFlag == True:
            break
##########################################################################

#########################2nd Phase Initialization#########################
    StrVecCore = [random.randint(0,15),random.randint(0,15)]
    StrVecMask = [0,random.randint(1,5),random.randint(6,10),random.randint(11,15)]
    StrVec[0] = StrVecCore
    for i in range (1,4):
        for j in range(0,2):
            StrVec[i][0] = (StrVecCore[0] + StrVecMask[i]) % 2
            StrVec[i][1] = StrVecCore[1]
    Round = 5
    Phase = 2
    impFlag = False
    recFlag = False
##########################################################################

#########################2nd Phase Precomputation#########################
    #It is possible that precomputed words is also utilized for the second phase. This step can be skipped.
##########################################################################

########################2nd Phase Data Collection#########################
    DataCollector(StrVec[0],PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList0 = ctxReader(CtxStr)
    DataCollector(StrVec[1],PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList1 = ctxReader(CtxStr)
    DataCollector(StrVec[2],PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList2 = ctxReader(CtxStr)
    DataCollector(StrVec[3],PtxStr,KeyStr,CtxStr,Round,Phase)
    CtxList3 = ctxReader(CtxStr)
    CtxBook = [CtxList0, CtxList1, CtxList2, CtxList3]
    for k0 in range(0,16):
        nibK0 = int2nib(k0)
        for k1 in range(0,16):
            nibK1 = int2nib(k1)
            Index = 16 * k0 + k1
            print("Phase2: ", (10000 * Index // 256) / 100, "% completed.")
##########################################################################

#######################2nd Phase 4-tuple extraction#######################
            for i in range(0,6):
                for j in range(0,6):
                    IndexQuad0 = 6 * i + j
                    X[0][0] = int2nib(Words[IndexQuad0][0])
                    X[0][1] = int2nib(Words[IndexQuad0][1])
                    for l in range(i + 1,6):
                        IndexQuad2 = 6 * l + j
                        X[2][0] = int2nib(Words[IndexQuad2][0])
                        X[2][1] = int2nib(Words[IndexQuad2][1])
                        for m in range(j + 1,6):
                            IndexQuad1 = 6 * l + m
                            IndexQuad3 = 6 * i + m
                            X[1][0] = int2nib(Words[IndexQuad1][0])
                            X[1][1] = int2nib(Words[IndexQuad1][1])
                            X[3][0] = int2nib(Words[IndexQuad3][0])
                            X[3][1] = int2nib(Words[IndexQuad3][1])
                            P[0][0] = Xor(X[0][1],nibK0)
                            P[1][0] = Xor(X[1][1],nibK0)
                            P[2][0] = Xor(X[2][1],nibK0)
                            P[3][0] = Xor(X[3][1],nibK0)
                            P[0][1] = Xor(X[0][0],nibK1)
                            P[1][1] = Xor(X[1][0],nibK1)
                            P[2][1] = Xor(X[2][0],nibK1)
                            P[3][1] = Xor(X[3][0],nibK1)
                            for St in range(0,4):
                                Num1 = nib2int(P[0][0])
                                Num2 = nib2int(P[0][1])
                                CtxList = CtxBook[St]
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
                                    impFlag = True
                                    break
                            if impFlag == True:
                                break
                        if impFlag == True:
                            break
                    if impFlag == True:
                        break
                if impFlag == True:
                    break
            if impFlag == False:
                RecKey[1][0] = int2nib(k0)
                RecKey[0][1] = int2nib(k1)
                recFlag = True
                print("Phase1: ", 100.0, "% completed.")
                break
            else:
                impFlag = False
        if recFlag == True:
            break
##########################################################################

###############################Key Recovery###############################
print("Recovered master key:")
print("\tBlock representation: ", [RecKey])
print("\tStream representation: ", end="")
for i in range(0,2):
    for j in range(0,2):
        for k in range(0,4):
            if k==3 and j==1 and i==1:
                print(RecKey[j][i][k])
            else:
                print(RecKey[j][i][k], end="")
print("\tHexadecimal representation: ", end="")
for i in range(0,2):
    for j in range(0,2):
        n = nib2int(RecKey[j][i])
        if n < 10:
            Str = chr(48 + n)
        else:
            Str = chr(87 + n)
            if j==1 and i==1:
                print(Str)
            else:
                print(Str, end="")
##########################################################################
