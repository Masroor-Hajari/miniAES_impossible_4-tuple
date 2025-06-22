#miniAES encryption Oracle.
#Insert 16-bit master key and chosen plaintext as a text file, named "miniAES_Ptx.txt."
#Oracle provides corresponding ciphertexts in the other text file, "miniAES_Ctx.txt."

from GFexp2by4 import int2nib, nib2int
from miniAES_Functions import AES_Enc

#################################str2num##################################
def str2num(st):
    u = ord(st)
    if u < 58:
        n = u - 48
    else:
        n = u - 87
    return n
##########################################################################

#################################num2str##################################    
def num2str(n):
    if n < 10:
        st = chr(48 + n)
    else:
        st = chr(87 + n) 
    return st
##########################################################################

################################KeyReader#################################
def keyReader(Name):
    f = open(Name)
    Str = f.read()
    f.close()
    Key = [[0] * 2 for i in range(2)] 
    Key[0][0] = str2num(Str[0])
    Key[1][0] = str2num(Str[1])
    Key[0][1] = str2num(Str[2])
    Key[1][1] = str2num(Str[3])
    return Key
##########################################################################

################################PtxReader#################################
def ptxReader(Name,StrVec,Phase):
    f = open(Name)
    Str = f.read()
    f.close()
    N = len(Str)
    M = (N + 1) // 3
    ctr = 0
    Arr = [[[0] * 2 for i in range(2)] for j in range(M)]
    for i in range(0,N):
        if i % 3 == 2:
            ctr += 1
            continue
        elif Phase == 1:
            Arr[ctr][i % 3][i % 3] = str2num(Str[i])
            Arr[ctr][i % 3][1 - (i % 3)] = StrVec[i % 3]
        else:
            Arr[ctr][1 - i % 3][i % 3] = str2num(Str[i])
            Arr[ctr][i % 3][i % 3] = StrVec[i % 3]
    return Arr
##########################################################################

################################CtxReader#################################
def ctxReader(Name):
    f = open(Name)
    Str = f.read()
    f.close()
    N = len(Str)
    M = (N + 1) // 5
    ctr = 0
    Arr = [[[0] * 2 for i in range(2)] for j in range(M)]
    for i in range(0,N):
        if i % 5 == 4:
            ctr += 1
            continue
        elif i % 5 == 0:
            Arr[ctr][0][0] = str2num(Str[i])
            Arr[ctr][1][0] = str2num(Str[i + 1])
            Arr[ctr][0][1] = str2num(Str[i + 2])
            Arr[ctr][1][1] = str2num(Str[i + 3])
        else:
            continue
    return Arr
##########################################################################

################################Generator#################################
#Generate the text file of the corresponding chosen plaintexts
def Generate(PtxFile,KeyFile,CtxFile,StrVec,Round,Phase):
    f = open(CtxFile,"w")
    f.close()
    PtxList = ptxReader(PtxFile,StrVec,Phase)
    mkNib = keyReader(KeyFile)
    MK = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    for i in range(0,2):
        for j in range(0,2):
            MK[i][j]=int2nib(mkNib[i][j])
    Len = len(PtxList)
    for i in range(0,Len - 1):
        Ptx = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
        for j in range(0,2):
            for k in range(0,2):
                Ptx[j][k] = int2nib(PtxList[i][j][k])
        Ctx = AES_Enc(Ptx,MK,Round)
        for j in range(0,2):
            for k in range(0,2):
                Number = nib2int(Ctx[k][j])
                String = num2str(Number)
                with open(CtxFile,"a") as f:
                    f.write(String)
        with open(CtxFile,"a") as f:
            f.write(",")
    Ptx = [[[0,0,0,0],[0,0,0,0]],[[0,0,0,0],[0,0,0,0]]]
    for i in range(0,2):
        for j in range(0,2):
            Ptx[i][j] = int2nib(PtxList[Len - 1][i][j])
    Ctx = AES_Enc(Ptx,MK,Round)
    for i in range(0,2):
        for j in range(0,2):
            Number = nib2int(Ctx[k][j])
            String = num2str(Number)
            with open(CtxFile,"a") as f:
                f.write(String)
    f.close()
##########################################################################    
