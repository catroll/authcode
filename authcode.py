#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import base64
import hashlib


class AuthCode(object):

    @classmethod
    def encode(cls, string, key, expiry=0):
        """
        编码
        @param string: 带编码字符串
        @param key: 密钥
        @return:加密字符串
        """
        return cls._auth_code(string, 'ENCODE', key, expiry)

    @classmethod
    def decode(cls, string, key, expiry=0):
        """
        解码
        @param string: 待解码字符串
        @param key: 密钥
        @return:原始字符串
        """
        return cls._auth_code(string, 'DECODE', key, expiry)

    @staticmethod
    def _md5(source_string):
        return hashlib.md5(source_string).hexdigest()

    @classmethod
    def _auth_code(cls, input_string, operation='DECODE', key='', expiry=3600):
        """
        编码/解码
        @param input_string: 原文或者密文
        @param operation: 操作（加密或者解密，默认是解密）
        @param key: 密钥
        @param expiry: 密文有效期，单位是秒，0 表示永久有效
        @return: 处理后的原文或者经过 base64_encode 处理后的密文
        """

        # 随机密钥长度 取值 0-32
        # 可以令密文无任何规律，即便是原文和密钥完全相同，加密结果也会每次不同，增大破解难度
        # 值越大，密文变动规律越大，密文变化 = 16 的 ckey_length 次方，如果为 0，则不产生随机密钥
        rand_key_length = 4

        ######################################################

        # 一 密钥通过拆解和变形参与加密和解密
        key = cls._md5(key)
        key_a = cls._md5(key[:16])
        key_b = cls._md5(key[16:])

        ######################################################

        # 二 加密：生成 rand_key，并处理 handling_string
        #    解密：分拆出 rand_key，handling_string
        if rand_key_length:
            if operation == 'DECODE':
                rand_key = input_string[:rand_key_length]
            else:
                rand_key = cls._md5(str(time.time()))[-rand_key_length:]
        else:
            rand_key = ''

        if operation == 'DECODE':
            handled_string = base64.b64decode(input_string[rand_key_length:])
        else:
            expiration_time = expiry + int(time.time) if expiry else 0
            handled_string = '%010d' % expiration_time + cls._md5(input_string + key_b)[:16] + input_string

        ######################################################

        # 三 生成加密解密密钥 crypt_key，并用其生成按位异或表
        #    input  : key_a, rand_key
        #    output : xor_table
        crypt_key = key_a + cls._md5(key_a + rand_key)
        # 其实这个地方起到的效果就相当于将 crypt_key * 4，然后逐位 ord
        crypt_key = [ord(crypt_key[i % len(crypt_key)]) for i in xrange(256)]
        xor_table = range(256)
        j = 0
        for i in xrange(256):
            j = (j + xor_table[i] + crypt_key[i]) % 256
            tmp = xor_table[i]
            xor_table[i] = xor_table[j]
            xor_table[j] = tmp

        # for i in xrange(len(xor_table)):
        #     print str(xor_table[i]).rjust(5),
        #     if ((i + 1) % 10) == 0:
        #         print ''

        ######################################################

        # 四 移位的一个异或
        #    因为本步骤中，table 没变，所以移位的异或没有改变异或的本质
        #    如果重复一遍就能得到原来的数据
        result = ''
        a = 0
        j = 0
        for i in xrange(len(handled_string)):
            a = (a + 1) % 256
            j = (j + xor_table[a]) % 256
            tmp = xor_table[a]
            xor_table[a] = xor_table[j]
            xor_table[j] = tmp
            result += chr(ord(handled_string[i]) ^ (xor_table[(xor_table[a] + xor_table[j]) % 256]))

        ######################################################

        # 五 第二步的反操作
        #    加密： 得到最终密文
        #    解密： 的到最终明文
        if operation == 'DECODE':
            if (int(result[:10]) == 0 or (int(result[:10]) - time.time() > 0)) and \
                    (result[10:26] == cls._md5(result[26:] + key_b)[:16]):
                output_string = result[26:]
            else:
                output_string = ''
        else:
            output_string = rand_key + base64.b64encode(result)

        return output_string

if __name__ == '__main__':
    src = 'My name is Hu Ang, I\'m a programmer.'
    key = 'fr1e54b8t4n4m47'
    encoded_string = AuthCode.encode(src, key)
    decoded_string = AuthCode.decode(encoded_string, key)
    print 'Source String:', src
    print 'After Encode :', encoded_string
    print 'After Decode :', decoded_string
    print '----------------------------------------------'
    # 通过 PHP 方式加密得到的一个密文，然后用 Python 解密
    # $source_string = "My name is Hu Ang.";
    # $secret_key = 'fr1e54b8t4n4m47';
    # $encoded_string = authcode($source_string, 'ENCODE', $secret_key, 0);
    php_encoded_string = '82798mEQ6ouQo1rFrbSXT5EHVjZ0gH0WuuZDXd9us/q44JAhmPwBAFZqvwXhvnjgUOJ+5aYh5ed8zNL3cjTOGBY='
    print 'Decode string encoded via php:', AuthCode.decode(php_encoded_string, key)
    # PS：Python 方式加密过的字符串通过 PHP 解析也成功了。