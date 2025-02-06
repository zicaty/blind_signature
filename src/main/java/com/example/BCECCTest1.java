package com.example;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.util.Random;

public class BCECCTest1 {
    public static void main(String[] args)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // 下面获取盲签名过程的所有所需参数
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();
        // Use SM2 curve parameters from Bouncy Castle
        X9ECParameters sm2Parameters = ECUtil.getNamedCurveByName("sm2p256v1");
        // 基点参数G
        ECPoint G = sm2Parameters.getG();
        // 模数n
        BigInteger n = sm2Parameters.getN();
        ECParameterSpec ecParameterSpec = new ECParameterSpec(sm2Parameters.getCurve(), G, sm2Parameters.getN());
        // 生成公钥和私钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ecParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey pk = keyPair.getPublic();
        PrivateKey sk = keyPair.getPrivate();
        // 公钥参数Q
        ECPoint pkPoint = ((ECPublicKey) pk).getQ();
        // 私钥参数d
        BigInteger d = ((ECPrivateKey) sk).getD();

        // 用户
        // （1）本地方随机数alpha（下称a）
        BigInteger alpha = getNextRandomBigInteger(random, 32);

        // 测试用的待签名数据
        byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        // 下面开始正式计算过程
        // (1)签名者计算R=kG
        // 签名方随机数k
        BigInteger k = getNextRandomBigInteger(random, 32);
        ECPoint rPoint = G.multiply(k);
        // (2-1)用户计算A=R+aG
        ECPoint aG = G.multiply(alpha);
        ECPoint aPoint = rPoint.add(aG);
        // (2-2)计算t=Rx(A) mod n
        BigInteger x1 = getX(aPoint).mod(n);
        // (2-3)计算c=H(m||x1)
        byte[] tByte = x1.toByteArray();
        byte[] cByte = hashCombine(data, tByte);
        BigInteger c = new BigInteger(cByte);
        // (3)签名者计算s'=k-cd
        BigInteger cD = c.multiply(d);
        BigInteger sPrime = k.add(cD.negate());
        // (4)用户计算s=s'+alpha，s即为对原数据的盲签名
        BigInteger s = sPrime.add(alpha);

        // 签名验证：计算c==H(m||(Rx(cQ+sG) mod n))
        ECPoint cQ = pkPoint.multiply(c);
        ECPoint sG = G.multiply(s);
        ECPoint cQsG = cQ.add(sG);
        BigInteger cQsGx = getX(cQsG).mod(n);
        byte[] cQsGxByte = cQsGx.toByteArray();
        byte[] testByte = hashCombine(data, cQsGxByte);
        BigInteger test = new BigInteger(testByte);
        System.out.println(test.equals(c));
    }

    public static byte[] hashCombine(byte[] data1, byte[] data2) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA1");
        digest.update(data1);
        digest.update(data2);
        return digest.digest();
    }

    public static BigInteger getNextRandomBigInteger(Random random, int byteSize) {
        byte[] byteArray = new byte[byteSize];
        random.nextBytes(byteArray);
        return new BigInteger(byteArray);
    }

    public static BigInteger getX(ECPoint point) {
        return point.normalize().getXCoord().toBigInteger();
    }
}