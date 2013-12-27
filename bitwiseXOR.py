# -*- encoding: utf-8 -*-

import hashlib


def md5(source_string):
    return hashlib.md5(source_string).hexdigest()


def printt(table, note=''):

    if not isinstance(note, basestring) or note == '':
        note = 'Table'

    print (' %s ' % note).center(70, '-')

    for i in xrange(len(table)):
        if ((i + 1) % 10) == 1:
            print '%03d  ' % (i/10),
        print str(table[i]).rjust(5),
        if ((i + 1) % 10) == 0:
            print ''

    print '\n', '^' * 70


def xor_table(key1, key2):
    """
    生成加密解密密钥 crypt_key，并用其生成按位异或表
    """

    crypt_key = key1 + md5(key1 + key2)
    # print 'crypt_key', crypt_key, len(crypt_key)
    # print [ord(i) for i in crypt_key], len(crypt_key), len(key1)

    crypt_key = [ord(crypt_key[i % len(crypt_key)]) for i in xrange(256)]
    # print crypt_key[:64]
    # print crypt_key[64:128]
    # print crypt_key[128:192]
    # print crypt_key[192:]

    xor_table = range(256)
    j = 0
    for i in xrange(256):
        j = (j + xor_table[i] + crypt_key[i]) % 256
        tmp = xor_table[i]
        xor_table[i] = xor_table[j]
        xor_table[j] = tmp

    printt(xor_table, ' XOR TABLE ')
    return xor_table


def bitwiseXOR(handled_string, key_a, rand_key):
    """
    不是简单的异或，而好像是一个加密（移位）的异或
    """

    # 生成加密解密密钥 crypt_key，并用其生成按位异或表
    table = xor_table(key_a, rand_key)

    ######################################################

    # 移位的一个异或
    # 因为本步骤中，table 没变，所以移位的异或没有改变异或的本质
    result = ''
    a = 0
    j = 0
    table_tmp = list(table)
    for i in xrange(len(handled_string)):
        a = (a + 1) % 256
        j = (j + table[a]) % 256
        tmp = table[a]
        table[a] = table[j]
        table[j] = tmp
        result += chr(ord(handled_string[i]) ^ (table[(table[a] + table[j]) % 256]))

    printt(table, 'After Shift')
    printt([i for i in xrange(len(table_tmp)) if table_tmp[i] != table[i]], 'DIFF')

    return result

if __name__ == '__main__':
    sourcestr = u'Hello, world!'
    handled_1 = bitwiseXOR(sourcestr, md5('abcdefg'), md5('123456'))
    handled_2 = bitwiseXOR(handled_1, md5('abcdefg'), md5('123456'))
    print 'Source String :', sourcestr
    print 'Handled 1st   :', handled_1
    print 'Handled 2nd   :', handled_2
