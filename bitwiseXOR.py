# -*- encoding: utf-8 -*-

import hashlib

def md5(source_string):
    return hashlib.md5(source_string).hexdigest()

def bitwiseXOR(handling_string, key_a, key_c):

    crypt_key = key_a + md5(key_a + key_c)
    rand_key = list()
    for i in xrange(256):
        rand_key.append(ord(crypt_key[i % len(crypt_key)]))

    # print 'crypt_key', crypt_key, len(crypt_key)
    # print 'rand_key', rand_key, len(rand_key)

    ######################################################

    box = range(256)
    j = 0
    for i in xrange(256):
        j = (j + box[i] + rand_key[i]) % 256
        tmp = box[i]
        box[i] = box[j]
        box[j] = tmp

    """
    for i in xrange(len(box)):
        print str(box[i]).rjust(5),
        if ((i + 1) % 10) == 0:
            print ''
    """

    ######################################################

    result = ''
    a = 0
    j = 0
    for i in xrange(len(handling_string)):
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        tmp = box[a]
        box[a] = box[j]
        box[j] = tmp
        result += chr(ord(handling_string[i]) ^ (box[(box[a] + box[j]) % 256]))

    return result

if __name__ == '__main__':
    sourcestr = u'Hello, world!'
    handled_1 = bitwiseXOR(sourcestr, 'abcdefg', '123456')
    handled_2 = bitwiseXOR(handled_1, 'abcdefg', '123456')
    print 'Source String :', sourcestr
    print 'Handled 1st   :', handled_1
    print 'Handled 2nd   :', handled_2
