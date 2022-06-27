# authors: Jia Long Ji Qiu, Jiabo Wang
import time
import sys

t1 = time.time()

def DecodeHuffman(code, m2c):
    c2m = {value: key for key, value in m2c.items()}
    currentCode = ''
    i = 0
    message = ''
    while i < len(code):
        currentCode += code[i]
        if currentCode in c2m:
            message += c2m[currentCode]
            currentCode = ''
        i += 1
    return message

# Dictionary to recover the codified message, obtained with the encoder
m2c = {' ': '1', '0': '010100', '1': '011', '2': '000', '3': '0011', '4': '01011', '5': '01001', '6': '01000', '7': '00101', '8': '00100', '9': '010101'}

fr = open('pwned-passwords-sha1-v7.cdi', 'rb')
allBytes = fr.read()
fr.close()

# HEXA: 471985160 bytes
# DEC: 23094 bytes + 3 bits (011)
n = 471985160
hexCode = hex(int.from_bytes(allBytes[:n], byteorder="big"))[2:].upper()
huffmanCode = bin(int.from_bytes(allBytes[n:], byteorder="big"))[2:] + '011'

# Free up RAM memory
allBytes = bytearray(0)

numbers = DecodeHuffman(huffmanCode, m2c)

'''
# For debugging purposes
fw = open('./numbers-decode.txt', 'w')
fw.write(numbers)
fw.close()
'''

numbers = numbers.split('  ')
numbersList = []
previousNumber = 24230577
n = len(numbers)-2

for i in range(n, 0, -1):
    if numbers[i+1][0] == ' ' and numbers[i][0] == ' ':
        numbers.insert(i + 1, '1')

for n in numbers:
    if n[0] == ' ':
        zeros = int(n[1:], 10)
        for i in range(zeros):
            numbersList.append(str(previousNumber))
    else:
        currentNumber = previousNumber - int(n, 10)
        numbersList.append(str(currentNumber))
        previousNumber = currentNumber

j = 0
recovered = []
for i in range(0, len(hexCode), 40):
    recovered.append(hexCode[i:i+40] + ':' + numbersList[j])
    j += 1

recovered = '\n'.join(recovered) + '\n'

fw = open('recovered.txt', 'w')
fw.write(recovered)
fw.close()

t2 = time.time()
print('Uncompress time:', t2 - t1)
