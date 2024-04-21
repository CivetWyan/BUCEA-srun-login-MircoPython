# Connect to network 
import network
import re
import hashlib
import urequests
import usocket
import json
import time
import socket
import uhashlib
import math
import hashlib




class LoginManager:
    def get_sha1(self,value):
        return ''.join(['{:02x}'.format(byte) for byte in hashlib.sha1(value.encode()).digest()])
    class HMACMD5:
        class md5():
            rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

            # constants = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)] # precision is not enough
            constants = [3614090360, 3905402710, 606105819, 3250441966, 4118548399, 1200080426, 2821735955, 4249261313,
                         1770035416, 2336552879, 4294925233, 2304563134, 1804603682, 4254626195, 2792965006, 1236535329,
                         4129170786, 3225465664, 643717713, 3921069994, 3593408605, 38016083, 3634488961, 3889429448,
                         568446438, 3275163606, 4107603335, 1163531501, 2850285829, 4243563512, 1735328473, 2368359562,
                         4294588738, 2272392833, 1839030562, 4259657740, 2763975236, 1272893353, 4139469664, 3200236656,
                         681279174, 3936430074, 3572445317, 76029189, 3654602809, 3873151461, 530742520, 3299628645,
                         4096336452, 1126891415, 2878612391, 4237533241, 1700485571, 2399980690, 4293915773, 2240044497,
                         1873313359, 4264355552, 2734768916, 1309151649, 4149444226, 3174756917, 718787259, 3951481745]

            init_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

            functions = 16 * [lambda b, c, d: (b & c) | (~b & d)] + \
                        16 * [lambda b, c, d: (d & b) | (~d & c)] + \
                        16 * [lambda b, c, d: b ^ c ^ d] + \
                        16 * [lambda b, c, d: c ^ (b | ~d)]

            index_functions = 16 * [lambda i: i] + \
                              16 * [lambda i: (5 * i + 1) % 16] + \
                              16 * [lambda i: (3 * i + 5) % 16] + \
                              16 * [lambda i: (7 * i) % 16]

            def __init__(self):
                return

            def left_rotate(self, x, amount):
                x &= 0xFFFFFFFF
                return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

            def update(self, message):
                self.message = bytearray(message)  # copy our input into a mutable buffer
                orig_len_in_bits = (8 * len(self.message)) & 0xffffffffffffffff
                self.message.append(0x80)
                while len(self.message) % 64 != 56:
                    self.message.append(0)
                self.message += orig_len_in_bits.to_bytes(8, 'little')

                hash_pieces = self.init_values[:]

                for chunk_ofst in range(0, len(self.message), 64):
                    a, b, c, d = hash_pieces
                    chunk = self.message[chunk_ofst:chunk_ofst + 64]
                    for i in range(64):
                        f = self.functions[i](b, c, d)
                        g = self.index_functions[i](i)
                        to_rotate = a + f + self.constants[i] + int.from_bytes(chunk[4 * g:4 * g + 4], 'little')
                        new_b = (b + self.left_rotate(to_rotate, self.rotate_amounts[i])) & 0xFFFFFFFF
                        a, b, c, d = d, new_b, b, c

                    for i, val in enumerate([a, b, c, d]):
                        hash_pieces[i] += val
                        hash_pieces[i] &= 0xFFFFFFFF

                self.msg_digest = sum(x << (32 * i) for i, x in enumerate(hash_pieces))

            def digest(self):
                return self.msg_digest

            def hexdigest(self):
                raw = self.msg_digest.to_bytes(16, 'little')
                return '{:032x}'.format(int.from_bytes(raw, 'big'))
        def ljust(self,s, width, fillchar):
            """Left-justify a string or bytes."""
            if isinstance(s, bytes):
                if len(s) >= width:
                    return s
                else:
                    padding_length = width - len(s)
                    padding = fillchar * padding_length
                    return s + padding
            elif isinstance(s, str):
                if len(s) >= width:
                    return s
                else:
                    padding_length = width - len(s)
                    padding = fillchar * padding_length
                    return s + padding
            else:
                raise TypeError("ljust() argument must be str or bytes")

        def translate(self,input_bytes, translation_table):
            translated_bytes = bytearray()  # 创建一个可变字节数组来存储翻译后的结果

            # 遍历输入的字节串
            for byte in input_bytes:
                # 在翻译表中查找当前字节对应的翻译
                translated_byte = translation_table[byte] if byte in translation_table else byte
                # 将翻译后的字节添加到结果中
                translated_bytes.append(translated_byte)

            # 将结果转换为不可变字节串并返回
            return bytes(translated_bytes)

        def __init__(self, key, msg=None):
            self.md5CC = self.md5()
            key = key
            self.message = msg
            if len(key) > 64:
                self.md5CC.update(key)
                key = self.md5CC.digest()
            else:
                key = self.ljust(key, 64, b'\0')
            self.key = key
            trans_5C = b"""\\]^_XYZ[TUVWPQRSLMNOHIJKDEFG@ABC|}~\x7fxyz{tuvwpqrslmnohijkdefg`abc\x1c\x1d\x1e\x1f\x18\x19\x1a\x1b\x14\x15\x16\x17\x10\x11\x12\x13\x0c\r\x0e\x0f\x08\t\n\x0b\x04\x05\x06\x07\x00\x01\x02\x03<=>?89:;45670123,-./()*+$%&\' !"#\xdc\xdd\xde\xdf\xd8\xd9\xda\xdb\xd4\xd5\xd6\xd7\xd0\xd1\xd2\xd3\xcc\xcd\xce\xcf\xc8\xc9\xca\xcb\xc4\xc5\xc6\xc7\xc0\xc1\xc2\xc3\xfc\xfd\xfe\xff\xf8\xf9\xfa\xfb\xf4\xf5\xf6\xf7\xf0\xf1\xf2\xf3\xec\xed\xee\xef\xe8\xe9\xea\xeb\xe4\xe5\xe6\xe7\xe0\xe1\xe2\xe3\x9c\x9d\x9e\x9f\x98\x99\x9a\x9b\x94\x95\x96\x97\x90\x91\x92\x93\x8c\x8d\x8e\x8f\x88\x89\x8a\x8b\x84\x85\x86\x87\x80\x81\x82\x83\xbc\xbd\xbe\xbf\xb8\xb9\xba\xbb\xb4\xb5\xb6\xb7\xb0\xb1\xb2\xb3\xac\xad\xae\xaf\xa8\xa9\xaa\xab\xa4\xa5\xa6\xa7\xa0\xa1\xa2\xa3"""
            trans_36 = b"""67452301>?<=:;89&\'$%"# !./,-*+()\x16\x17\x14\x15\x12\x13\x10\x11\x1e\x1f\x1c\x1d\x1a\x1b\x18\x19\x06\x07\x04\x05\x02\x03\x00\x01\x0e\x0f\x0c\r\n\x0b\x08\tvwturspq~\x7f|}z{xyfgdebc`anolmjkhiVWTURSPQ^_\\]Z[XYFGDEBC@ANOLMJKHI\xb6\xb7\xb4\xb5\xb2\xb3\xb0\xb1\xbe\xbf\xbc\xbd\xba\xbb\xb8\xb9\xa6\xa7\xa4\xa5\xa2\xa3\xa0\xa1\xae\xaf\xac\xad\xaa\xab\xa8\xa9\x96\x97\x94\x95\x92\x93\x90\x91\x9e\x9f\x9c\x9d\x9a\x9b\x98\x99\x86\x87\x84\x85\x82\x83\x80\x81\x8e\x8f\x8c\x8d\x8a\x8b\x88\x89\xf6\xf7\xf4\xf5\xf2\xf3\xf0\xf1\xfe\xff\xfc\xfd\xfa\xfb\xf8\xf9\xe6\xe7\xe4\xe5\xe2\xe3\xe0\xe1\xee\xef\xec\xed\xea\xeb\xe8\xe9\xd6\xd7\xd4\xd5\xd2\xd3\xd0\xd1\xde\xdf\xdc\xdd\xda\xdb\xd8\xd9\xc6\xc7\xc4\xc5\xc2\xc3\xc0\xc1\xce\xcf\xcc\xcd\xca\xcb\xc8\xc9"""
            # iKeyPad = bytes((x ^ 0x36) for x in range(256))
            # oKeyPad = bytes((x ^ 0x5C) for x in range(256))
            iKeyPad = self.translate(key, trans_36)
            #print(f"{iKeyPad}")
            oKeyPad = self.translate(key, trans_5C)
            #print(f"{oKeyPad}")
            self.md5CC.update(iKeyPad)
            # bytes.fromhex
            self.inner = bytes.fromhex(self.md5CC.hexdigest())
            # DDD:b'\x80\x91#\xf5\x99\xe1\x84\x84\x8av\xf8\x8c\x07W~\r'
            # b'\x80\x91#\xf5\x99\xe1\x84\x84\x8av\xf8\x8c\x07W~\r'
            # b'\x07666666666666666666666666666666666666666666666666666666666666666'
            # b'+]\xda&K\xeb5Ntf7\x96\xf3\xda\xab\xe0'
            # b'+]\xda&K\xeb5Ntf7\x96\xf3\xda\xab\xe0'
            self.md5CC.update(oKeyPad)
            self.outer = bytes.fromhex(self.md5CC.hexdigest())
            if msg is not None:
                self.update(msg)

        def update(self, msg):
            trans_36 = b"""67452301>?<=:;89&\'$%"# !./,-*+()\x16\x17\x14\x15\x12\x13\x10\x11\x1e\x1f\x1c\x1d\x1a\x1b\x18\x19\x06\x07\x04\x05\x02\x03\x00\x01\x0e\x0f\x0c\r\n\x0b\x08\tvwturspq~\x7f|}z{xyfgdebc`anolmjkhiVWTURSPQ^_\\]Z[XYFGDEBC@ANOLMJKHI\xb6\xb7\xb4\xb5\xb2\xb3\xb0\xb1\xbe\xbf\xbc\xbd\xba\xbb\xb8\xb9\xa6\xa7\xa4\xa5\xa2\xa3\xa0\xa1\xae\xaf\xac\xad\xaa\xab\xa8\xa9\x96\x97\x94\x95\x92\x93\x90\x91\x9e\x9f\x9c\x9d\x9a\x9b\x98\x99\x86\x87\x84\x85\x82\x83\x80\x81\x8e\x8f\x8c\x8d\x8a\x8b\x88\x89\xf6\xf7\xf4\xf5\xf2\xf3\xf0\xf1\xfe\xff\xfc\xfd\xfa\xfb\xf8\xf9\xe6\xe7\xe4\xe5\xe2\xe3\xe0\xe1\xee\xef\xec\xed\xea\xeb\xe8\xe9\xd6\xd7\xd4\xd5\xd2\xd3\xd0\xd1\xde\xdf\xdc\xdd\xda\xdb\xd8\xd9\xc6\xc7\xc4\xc5\xc2\xc3\xc0\xc1\xce\xcf\xcc\xcd\xca\xcb\xc8\xc9"""
            con = self.translate(self.key, trans_36) + msg
            self.md5CC.update(con)
            self.inner = bytes.fromhex(self.md5CC.hexdigest())
            # b'q3\x0c\xa2v\xd4\x0f\xe9`\xe7<O\xfd0@\xb0'
            # b'\xc6P\x8f\x97\x17F\xd3\xa7\x92\xa4\xd2_\xfa}D\xec'

        def get(self):
            return self.md5CC.hexdigest()

        def hexdigest(self):
            trans_5C = b"""\\]^_XYZ[TUVWPQRSLMNOHIJKDEFG@ABC|}~\x7fxyz{tuvwpqrslmnohijkdefg`abc\x1c\x1d\x1e\x1f\x18\x19\x1a\x1b\x14\x15\x16\x17\x10\x11\x12\x13\x0c\r\x0e\x0f\x08\t\n\x0b\x04\x05\x06\x07\x00\x01\x02\x03<=>?89:;45670123,-./()*+$%&\' !"#\xdc\xdd\xde\xdf\xd8\xd9\xda\xdb\xd4\xd5\xd6\xd7\xd0\xd1\xd2\xd3\xcc\xcd\xce\xcf\xc8\xc9\xca\xcb\xc4\xc5\xc6\xc7\xc0\xc1\xc2\xc3\xfc\xfd\xfe\xff\xf8\xf9\xfa\xfb\xf4\xf5\xf6\xf7\xf0\xf1\xf2\xf3\xec\xed\xee\xef\xe8\xe9\xea\xeb\xe4\xe5\xe6\xe7\xe0\xe1\xe2\xe3\x9c\x9d\x9e\x9f\x98\x99\x9a\x9b\x94\x95\x96\x97\x90\x91\x92\x93\x8c\x8d\x8e\x8f\x88\x89\x8a\x8b\x84\x85\x86\x87\x80\x81\x82\x83\xbc\xbd\xbe\xbf\xb8\xb9\xba\xbb\xb4\xb5\xb6\xb7\xb0\xb1\xb2\xb3\xac\xad\xae\xaf\xa8\xa9\xaa\xab\xa4\xa5\xa6\xa7\xa0\xa1\xa2\xa3"""
            con = self.translate(self.key, trans_5C) + self.inner
            self.md5CC.update(con)
            return self.md5CC.hexdigest()

    def get_token(self):
        c_url = "http://10.1.1.131/cgi-bin/get_challenge?username="+self.username+"&ip="+ self.ip + "&callback=" + "jQuery111000_" + str(self.st)
        a = urequests.get(c_url)
        print(a.text)
        Cdata = json.loads(re.search(r'(\{.*?\})', a.text).group(1))
        challenge = Cdata["challenge"]
        self.token = challenge
        a.close()
    def get_time(self):
        def _encode_params(params):
            return "&".join([f"{k}={v}" for k, v in params.items()])
        def get_with_params(url, params=None, headers={}):
            if params:
                if "?" in url:
                    url += "&" + _encode_params(params)
                else:
                    url += "?" + _encode_params(params)
            return url
        srun_portal_params={
        'callback': 'jQuery11240645308969735664_'+str(int(time.time()*1000)),
        'action':'login',
        "username":self.username,
        "password":"1",
        "type":self.type,
        "n":self.n
        }
        #print("In")
        # print(srun_portal_params)
        z = get_with_params(url=self.srun_portal_api,params=srun_portal_params)
        #print(z)
        srun_portal_res=urequests.get(z)
        #print("123")
        #print(srun_portal_res.text)
        #print("OK")
        Cdata = json.loads(re.search(r'(\{.*?\})', srun_portal_res.text).group(1))
        st = int(Cdata["st"])*1000
        srun_portal_res.close()
        self.st = st
    def get_info(self):
        info_temp={
            "username":self.username,
            "password":self.password,
            "ip":self.ip,
            "acid":self.ac_id,
            "enc_ver":self.enc
        }
        i=re.sub("'",'"',str(info_temp))
        i=re.sub(" ",'',i)
        self.i = i
        return i
    def get_sha1(self,value):
        return ''.join(['{:02x}'.format(byte) for byte in hashlib.sha1(value.encode()).digest()])
    def __init__(self,username,password,SSID="BUCEA",SSIDPASSWORD=None):
        self.n = '200'
        self.type = '1'
        self.SSID = SSID
        if SSID=="BUCEA":
            self.ac_id='11'
        else:
            self.ac_id='1'
        self.enc = "srun_bx1"
        self.username = "202107040139"
        self.password = "!Zz12345678"
        self.srun_portal_api="http://10.1.1.131/cgi-bin/srun_portal"
        
        self.header={
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
        }
        self.SSIDPASSWORD = SSIDPASSWORD
    
    



    def get_xencode(self,msg, key):
        
        def force(msg):
            ret = []
            for w in msg:
                ret.append(ord(w))
            return bytes(ret)
    
    
        def ordat(msg, idx):
            if len(msg) > idx:
                return ord(msg[idx])
            return 0


        def sencode(msg, key):
            l = len(msg)
            pwd = []
            for i in range(0, l, 4):
                pwd.append(
                    ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
                    | ordat(msg, i + 3) << 24)
            if key:
                pwd.append(l)
            return pwd


        def lencode(msg, key):
            l = len(msg)
            ll = (l - 1) << 2
            if key:
                m = msg[l - 1]
                if m < ll - 3 or m > ll:
                    return
                ll = m
            for i in range(0, l):
                msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
                    msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
            if key:
                return "".join(msg)[0:ll]
            return "".join(msg)

        if msg == "":
            return ""
        pwd = sencode(msg, True)
        pwdk = sencode(key, False)
        if len(pwdk) < 4:
            pwdk = pwdk + [0] * (4 - len(pwdk))
        n = len(pwd) - 1
        z = pwd[n]
        y = pwd[0]
        c = 0x86014019 | 0x183639A0
        m = 0
        e = 0
        p = 0
        q = math.floor(6 + 52 / (n + 1))
        d = 0
        while 0 < q:
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = d >> 2 & 3
            p = 0
            while p < n:
                y = pwd[p + 1]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (pwdk[(p & 3) ^ e] ^ z)
                pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = pwd[p]
                p = p + 1
            y = pwd[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
            z = pwd[n]
            q = q - 1
        return lencode(pwd, False)








    def get_base64(self,s):
        _PADCHAR = "="
        _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
        def _getbyte(s, i):
            x = ord(s[i])
            if (x > 255):
                print("INVALID_CHARACTER_ERR: DOM Exception 5")
                exit(0)
            return x
        i = 0
        b10 = 0
        x = []
        imax = len(s) - len(s) % 3
        if len(s) == 0:
            return s
        for i in range(0, imax, 3):
            b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
            x.append(_ALPHA[(b10 >> 18)])
            x.append(_ALPHA[((b10 >> 12) & 63)])
            x.append(_ALPHA[((b10 >> 6) & 63)])
            x.append(_ALPHA[(b10 & 63)])
        i = imax
        if len(s) - imax == 1:
            b10 = _getbyte(s, i) << 16
            x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR)
        elif len(s) - imax == 2:
            b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8)
            x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _ALPHA[((b10 >> 6) & 63)] + _PADCHAR)
        else:
            # do nothing
            pass
        return "".join(x)

    def quote(self,s, safe='/'):
        always_safe = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                       'abcdefghijklmnopqrstuvwxyz'
                       '0123456789' '_.-')
        safe += always_safe
        safe_map = {}
        for i in range(256):
            c = chr(i)
            safe_map[c] = (c if (c in always_safe or c in safe) else
                           ('%%%02X' % i))
        return ''.join([safe_map[c] for c in s])
    
    
    
    
    def login(self):
        self.wlan = network.WLAN(network.STA_IF)
        self.wlan.active(True)
        if self.SSIDPASSWORD==None:
            self.wlan.connect(self.SSID)
            ip = self.wlan.ifconfig()[0]
            while ip=="0.0.0.0":
                time.sleep(2)
                self.wlan.connect(self.SSID)
                ip = self.wlan.ifconfig()[0]
            ip = self.wlan.ifconfig()[0]
            print(f"本机IP为{ip}")
            self.ip = ip
        else:
            self.wlan.connect(self.SSID,self.SSIDPASSWORD)
            ip = self.wlan.ifconfig()[0]
            while ip=="0.0.0.0":
                time.sleep(2)
                self.wlan.connect(self.SSID,self.SSIDPASSWORD)
                ip = self.wlan.ifconfig()[0]
            ip = self.wlan.ifconfig()[0]
            print(f"本机IP为{ip}")
            self.ip = ip
        
        self.get_time()
        self.get_info()
        self.get_token()
        #print(self.token)
        self.encrypted_info = "{SRBX1}" + self.get_base64(self.get_xencode(self.i,self.token))
        h = self.HMACMD5(self.token.encode(),"".encode())
        self.hmd5 = h.hexdigest()
        self.encrypted_md5 = "{MD5}" + self.hmd5
        #print(self.encrypted_md5)
        chkstr = self.token + self.username
        chkstr += self.token + self.hmd5
        chkstr += self.token + f"{self.ac_id}"
        chkstr += self.token + self.ip
        chkstr += self.token + "200"
        chkstr += self.token + "1"
        chkstr += self.token + self.encrypted_info
        self.encrypted_chkstr = self.get_sha1(chkstr)
        #print(self.encrypted_chkstr)
        #print(self.encrypted_info)
        login_url = "http://10.1.1.131/cgi-bin/srun_portal?callback=jQuery112406864159535783183_1678368115385&action=login" + \
            "&username=" + self.username +\
            "&password=" + self.quote(self.encrypted_md5)+ \
            "&os=Windows+10" +\
            "&name=Windows" +\
            "&double_stack=0" +\
            "&chksum=" + self.encrypted_chkstr + \
            "&info=" + self.quote(self.encrypted_info) +\
            "&ac_id=" + self.ac_id + \
            "&ip=" + self.ip + \
            "&n=200" + \
            "&type=1"
        res = urequests.get(url=login_url).text
        print(res)
        print("登录完成")
        


