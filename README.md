# miniAES_impossible_4-tuple
Applying the cryptanalysis method to the impossible 4-tuple of the 5-round miniAES block cipher.

This package can apply the novel cryptanalysis method, "impossible 4-tuple cryptanalysis", to the miniAES algorithm.
It is possible to recover the key of this algorithm with the following two methods.
	1. Typical impossible 4-tuple cryptanalysis
	2. Fast impossible 4-tuple cryptanalysis

To use this package to recover the 5-round miniAES algorithm, please follow the instructions below:
1. Add the package files in the directory where the Python compiler has been installed, for example, "C:\Users\myAccount\AppData\Local\Programs\Python\Python310".
2. Enter the secret key of the miniAES algorithm in the text file "miniAES_Key.txt". Since the algorithm uses a 16-bit master key, the entered key in "miniAES_Key.txt" shall contain four hexadecimal characters (without using any capital letters), for example, "f345".
3. To recover the master key via the "typical version", open the "cmd", and then write the command "python.exe miniAES_Typical_Imp_4tuple.py".
4. Also, it is possible to recover the key with the "fast version" by running the command "python.exe miniAES_Fast_Imp_4tuple.py".
