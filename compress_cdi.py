# authors: Jia Long Ji Qiu, Jiabo Wang
import time
import collections

t1 = time.time()

def Huffman(p):
    if p == [1]:
        return ['0']
    def Tree():
        return collections.defaultdict(Tree)
    nodes = list(zip(sorted(p),[Tree()]*len(p)))
    while len(nodes) > 1:
        new_node = Tree()
        new_node[0] = nodes[0]
        new_node[1] = nodes[1]
        nodes.append(tuple((nodes[0][0]+nodes[1][0],new_node)))
        del(nodes[0])
        del(nodes[0])
        nodes.sort(key = lambda x: x[0])
    t = nodes[0]
    def traverse_tree(tree, prefix='', code=[]):
        if 0 in tree[1]:
            traverse_tree(tree[1][0],prefix+'0',code)
        if 1 in tree[1]:
            traverse_tree(tree[1][1],prefix+'1',code)
        else:
            code.append((prefix,tree[0]))
        return code
    code = traverse_tree(t)
    codigo = []
    for e in p:
        index_to_del = None
        for index, value in enumerate(code):
            if e == value[1]:
                index_to_del = index
                codigo.append(value[0])
                break
        del(code[index_to_del])
    return codigo
    
def getFrequencies(mensaje):
    frequencies = {}
    for c in mensaje:
        if c not in frequencies:
            frequencies[c] = 1
        else:
            frequencies[c] += 1
    frequencies = sorted(list(frequencies.items()))
    return [list(e) for e in frequencies]

def EncodeHuffman(message):
    frequencies = getFrequencies(message)
    chars = [item[0] for item in frequencies]
    ps = [item[1] for item in frequencies]
    total = sum(ps)
    ps = list(map(lambda x: x/total,ps))
    code = Huffman(ps)
    m2c =  dict(zip(chars, code))
    codified = ''
    for char in message:
        codified = codified + m2c[char]
    return codified, m2c

# File read
f = open('pwned-passwords-sha1-ordered-by-count-v7_reducido.txt', 'r')
L = f.read().split('\n')
L.pop()

# Compression
hexBytes = bytearray(0)
numbers = ''
previousNumber = 24230577
zeroAcc = 0
oneSkipped = False
for line in L:

    hexBytes += bytearray(int(line[x:x+2], 16) for x in range(0, 40, 2))

    currentNumber = int(line[41:], 10)
    diff = previousNumber - currentNumber

    if diff == 0:
        zeroAcc += 1
    else:
        if zeroAcc > 0:
            if diff == 1:
                numbers += ' ' + str(zeroAcc) + '  '
                oneSkipped = True
            else:
                if oneSkipped:
                    oneSkipped = False
                numbers += ' ' + str(zeroAcc) + '  ' + str(diff) + '  '
            zeroAcc = 0
        else:
            if oneSkipped:
                oneSkipped = False
                numbers += '1  '
            numbers += str(diff) + '  '
    previousNumber = currentNumber

if zeroAcc > 0:
    numbers += ' ' + str(zeroAcc)

code, m2c = EncodeHuffman(numbers)

# Prints the dictionary used for uncompressing
print('m2c =', m2c)

'''
# For debugging purposes
fw = open('./numbers-encode.txt', 'w')
fw.write(numbers)
fw.close()
'''

divisor = (len(code)//8) * 8
lastBin = code[divisor:]
code = code[:divisor]

# Prints the last bits of the Huffman code in case it is not multiple of 8
print('lastBin =', lastBin)

huffmanBytes = bytearray(int(code[x:x+8], 2) for x in range(0, len(code), 8))

print('Hexadecimal code has a length of %d bytes' % len(hexBytes))
print('Huffman code has a length of %d bytes and %d bits' % (len(huffmanBytes), len(lastBin)))

fw = open('./pwned-passwords-sha1-v7.cdi', 'wb')
fw.write(hexBytes + huffmanBytes)
fw.close()

totalBytes = len(huffmanBytes) + len(hexBytes)
print("The compressed file has a size of %d bytes, the ratio is %f" % (totalBytes, 1040864729/totalBytes))

t2 = time.time()
print('Compress time:', t2-t1)
