from random import choice
import SM3
# 选择素域，设置椭圆曲线参数
sm2_N = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
sm2_P = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
sm2_G = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0'  # G点
sm2_a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',16)
sm2_b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',16)
sm2_a_3 = (sm2_a + 3) % sm2_P # 倍点用到的中间值
Fp = 256

# sm2_N = int('BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677', 16)
# sm2_P = int('BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F', 16)
# sm2_G = '4AD5F7048DE709AD51236DE65E4D4B482C836DC6E410664002BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2'# G点
# sm2_a = int('BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985',16)
# sm2_b = int('1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1',16)
# sm2_a_3 = (sm2_a + 3) % sm2_P # 倍点用到的中间值
# Fp = 192

def get_random_str(strlen):
    letterlist = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    str = ''
    for i in range(strlen):
        a = choice(letterlist)
        str = '%s%s' % (str,a)
    return str

def kG(k, Point,len_para):  # kP运算
    Point = '%s%s' % (Point, '1')
    mask_str = '8'
    for i in range(len_para-1):
        mask_str += '0'
    # print(mask_str)
    mask = int(mask_str, 16)
    Temp = Point
    flag = False
    for n in range(len_para * 4):
        if (flag):
            Temp = DoublePoint(Temp,len_para)
        if (k & mask) != 0:
            if (flag):
                Temp = AddPoint(Temp, Point,len_para)
            else:
                flag = True
                Temp = Point
        k = k << 1
    return ConvertJacb2Nor(Temp,len_para)

def DoublePoint(Point,len_para):  # 倍点
    l = len(Point)
    len_2 = 2 * len_para
    if l< len_para*2:
        return None
    else:
        x1 = int(Point[0:len_para], 16)
        y1 = int(Point[len_para:len_2], 16)
        if l == len_2:
            z1 = 1
        else:
            z1 = int(Point[len_2:], 16)
        T6 = (z1 * z1) % sm2_P
        T2 = (y1 * y1) % sm2_P
        T3 = (x1 + T6) % sm2_P
        T4 = (x1 - T6) % sm2_P
        T1 = (T3 * T4) % sm2_P
        T3 = (y1 * z1) % sm2_P
        T4 = (T2 * 8) % sm2_P
        T5 = (x1 * T4) % sm2_P
        T1 = (T1 * 3) % sm2_P
        T6 = (T6 * T6) % sm2_P
        T6 = (sm2_a_3 * T6) % sm2_P
        T1 = (T1 + T6) % sm2_P
        z3 = (T3 + T3) % sm2_P
        T3 = (T1 * T1) % sm2_P
        T2 = (T2 * T4) % sm2_P
        x3 = (T3 - T5) % sm2_P

        if (T5 % 2) == 1:
            T4 = (T5 + ((T5 + sm2_P) >> 1) - T3) % sm2_P
        else:
            T4 = (T5 + (T5 >> 1) - T3) % sm2_P

        T1 = (T1 * T4) % sm2_P
        y3 = (T1 - T2) % sm2_P

        form = '%%0%dx' % len_para
        form = form * 3
        return form % (x3, y3, z3)

def AddPoint(P1, P2,len_para):  # 点加函数，P2点为仿射坐标即z=1，P1为Jacobian加重射影坐标
    len_2 = 2 * len_para
    l1 = len(P1)
    l2 = len(P2)
    if (l1 < len_2) or (l2 < len_2):
        return None
    else:
        X1 = int(P1[0:len_para], 16)
        Y1 = int(P1[len_para:len_2], 16)
        if (l1 == len_2):
            Z1 = 1
        else:
            Z1 = int(P1[len_2:], 16)
        x2 = int(P2[0:len_para], 16)
        y2 = int(P2[len_para:len_2], 16)

        T1 = (Z1 * Z1) % sm2_P
        T2 = (y2 * Z1) % sm2_P
        T3 = (x2 * T1) % sm2_P
        T1 = (T1 * T2) % sm2_P
        T2 = (T3 - X1) % sm2_P
        T3 = (T3 + X1) % sm2_P
        T4 = (T2 * T2) % sm2_P
        T1 = (T1 - Y1) % sm2_P
        Z3 = (Z1 * T2) % sm2_P
        T2 = (T2 * T4) % sm2_P
        T3 = (T3 * T4) % sm2_P
        T5 = (T1 * T1) % sm2_P
        T4 = (X1 * T4) % sm2_P
        X3 = (T5 - T3) % sm2_P
        T2 = (Y1 * T2) % sm2_P
        T3 = (T4 - X3) % sm2_P
        T1 = (T1 * T3) % sm2_P
        Y3 = (T1 - T2) % sm2_P

        form = '%%0%dx' % len_para
        form = form * 3
        return form % (X3, Y3, Z3)

def ConvertJacb2Nor(Point,len_para): # Jacobian加重射影坐标转换成仿射坐标
    len_2 = 2 * len_para
    x = int(Point[0:len_para], 16)
    y = int(Point[len_para:len_2], 16)
    z = int(Point[len_2:], 16)
    # z_inv = Inverse(z, P)
    z_inv = pow(z, sm2_P - 2, sm2_P)
    z_invSquar = (z_inv * z_inv) % sm2_P
    z_invQube = (z_invSquar * z_inv) % sm2_P
    x_new = (x * z_invSquar) % sm2_P
    y_new = (y * z_invQube) % sm2_P
    z_new = (z * z_inv) % sm2_P
    if z_new == 1:
        form = '%%0%dx' % len_para
        form = form * 2
        return form % (x_new, y_new)
    else:
        print ("Point at infinity!!!!!!!!!!!!")
        return None

def Inverse(data, M,len_para):  # 求逆，可用pow（）代替
    tempM = M - 2
    mask_str = '8'
    for i in range(len_para-1):
        mask_str += '0'
    mask = int(mask_str, 16)
    tempA = 1
    tempB = data

    for i in range(len_para*4):
        tempA = (tempA * tempA) % M
        if (tempM & mask) != 0:
            tempA = (tempA * tempB) % M
        mask = mask >> 1

    return tempA

def Verify(Sign, E, PA,len_para):  # 验签函数，Sign签名r||s，E消息hash，PA公钥
    r = int(Sign[0:len_para], 16)
    s = int(Sign[len_para:2*len_para], 16)
    e = int(E, 16)
    t = (r + s) % sm2_N
    if t == 0:
        return 0

    P1 = kG(s, sm2_G,len_para)
    P2 = kG(t, PA,len_para)
    # print(P1)
    # print(P2)
    if P1 == P2:
        P1 = '%s%s' % (P1, 1)
        P1 = DoublePoint(P1,len_para)
    else:
        P1 = '%s%s' % (P1, 1)
        P1 = AddPoint(P1, P2,len_para)
        P1 = ConvertJacb2Nor(P1,len_para)

    x = int(P1[0:len_para], 16)
    return (r == ((e + x) % sm2_N))

def Sign(E, DA, K,len_para,Hexstr = 0):  # 签名函数, E消息的hash，DA私钥，K随机数，均为16进制字符串
    if Hexstr:
        e = int(E, 16) # 输入消息本身是16进制字符串
    else:
        E = E.encode('utf-8')
        E = E.hex() # 消息转化为16进制字符串
        e = int(E, 16)

    d = int(DA, 16)
    k = int(K, 16)

    P1 = kG(k, sm2_G,len_para)

    x = int(P1[0:len_para], 16)
    R = ((e + x) % sm2_N)
    if R == 0 or R + k == sm2_N:
        return None
    d_1 = pow(d+1, sm2_N - 2, sm2_N)
    S = (d_1*(k + R) - R) % sm2_N
    if S == 0:
        return None
    else:
        return '%064x%064x' % (R,S)

def Encrypt(M,PA,len_para,Hexstr = 0):# 加密函数，M消息，PA公钥
    if Hexstr:
        msg = M # 输入消息本身是16进制字符串
    else:
        msg = M.encode('utf-8')
        msg = msg.hex() # 消息转化为16进制字符串
    k = get_random_str(len_para)
    # k = '59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21'
    # k = '384F30353073AEECE7A1654330A96204D37982A3E15B2CB5'
    C1 = kG(int(k,16),sm2_G,len_para)
    # print('C1 = %s'%C1)
    xy = kG(int(k,16),PA,len_para)
    # print('xy = %s' % xy)
    x2 = xy[0:len_para]
    y2 = xy[len_para:2*len_para]
    ml = len(msg)
    # print('ml = %d'% ml)
    t = SM3.KDF(xy,ml/2)
    # print(t)
    if int(t,16)==0:
        return None
    else:
        form = '%%0%dx' % ml
        C2 = form % (int(msg,16) ^ int(t,16))
        # print('C2 = %s'% C2)
        # print('%s%s%s'% (x2,msg,y2))
        C3 = SM3.Hash_sm3('%s%s%s'% (x2,msg,y2),1)
        # print('C3 = %s' % C3)
        return '%s%s%s' % (C1,C3,C2)

def Decrypt(C,DA,len_para):# 解密函数，C密文（16进制字符串），DA私钥
    len_2 = 2 * len_para
    len_3 = len_2 + 64
    C1 = C[0:len_2]
    C3 = C[len_2:len_3]
    C2 = C[len_3:]
    xy = kG(int(DA,16),C1,len_para)
    # print('xy = %s' % xy)
    x2 = xy[0:len_para]
    y2 = xy[len_para:len_2]
    cl = len(C2)
    # print(cl)
    t = SM3.KDF(xy, cl/2)
    # print('t = %s'%t)
    if int(t,16) == 0:
        return None
    else:
        form = '%%0%dx' % cl
        M = form % (int(C2,16) ^ int(t,16))
        # print('M = %s' % M)
        u = SM3.Hash_sm3('%s%s%s'% (x2,M,y2),1)
        if  (u == C3):
            return M
        else:
            return None


if __name__ == '__main__':
    len_para = int(Fp / 4)
    print(len_para)
    e = get_random_str(len_para)
    d = get_random_str(len_para)
    k = get_random_str(len_para)
    # e = '656E6372797074696F6E207374616E64617264'
    d = '3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8'
    # d = '58892B807074F53FBF67288A1DFAA1AC313455FE60355AFD'
    Pa = kG(int(d, 16), sm2_G,len_para)
    Sig = Sign(e,d,k,len_para,1)
    print(Verify(Sig,e,Pa,len_para))
    print(Pa)
    e = "你好"
    print('M = %s' % e)
    C = Encrypt(e,Pa,len_para,0)
    print('C = %s' % C)
    print('Decrypt')
    m = Decrypt(C,d,len_para)
    M = bytes.fromhex(m)
    print(M.decode())

    # e  = '00ce5d9489d867867096326f3842323ab0a2f7f893181bae4dc9d4cd7ed50f31'
    # D  = '1d06dc143f1725f7eeae8a0ae94ebc62fbe4407c99a90950e46d29e7645000cb'
    # K  = '8e00000000000000000000000000000000000000000000000000000000000000'
    # Px = '000000000000000000000000000000000000000000000000f100000000000000'
    # Py = '0000000000000000000000000000000000000000000000000000000000000000'
    # print(Verify(D+K, e, Px+Py, len_para))
