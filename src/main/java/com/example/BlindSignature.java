// 杨彬给的
// 能正确验签，但是签名过程跟ECDSA不一致
package com.example;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

public class BlindSignature {

    private static final String CURVE_NAME = "secp256r1"; // 也称为 P-256
    private static final X9ECParameters ecParams = SECNamedCurves.getByName(CURVE_NAME);
    private static final ECDomainParameters domainParams = new ECDomainParameters(
            ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());
    private static final SecureRandom secureRandom = new SecureRandom();

    private BigInteger privateKey;
    private ECPoint publicKey;

    public BlindSignature() {
        this.privateKey = new BigInteger(domainParams.getN().bitLength(), secureRandom);
        while (this.privateKey.compareTo(BigInteger.ZERO) <= 0 || this.privateKey.compareTo(domainParams.getN()) >= 0) {
            this.privateKey = new BigInteger(domainParams.getN().bitLength(), secureRandom); // 确保私钥在范围内
        }
        this.publicKey = calculatePublicKey(this.privateKey);
    }

    // 计算公钥
    private ECPoint calculatePublicKey(BigInteger privateKey) {
        FixedPointCombMultiplier multiplier = new FixedPointCombMultiplier();
        return multiplier.multiply(domainParams.getG(), privateKey);
    }

    // 哈希消息
    private BigInteger hashMessage(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, hashBytes); // 1 表示正数
    }

    // 生成盲化因子
    private BigInteger generateBlindingFactor() {
        BigInteger blindingFactor;
        do {
            blindingFactor = new BigInteger(domainParams.getN().bitLength(), secureRandom);
        } while (blindingFactor.compareTo(BigInteger.ZERO) <= 0 || blindingFactor.compareTo(domainParams.getN()) >= 0);
        return blindingFactor;
    }

    // 盲化消息
    public BigInteger blindMessage(String message, BigInteger blindingFactor) throws NoSuchAlgorithmException {
        BigInteger hashedMessage = hashMessage(message);
        return hashedMessage.multiply(blindingFactor).mod(domainParams.getN());
    }

    // 签名
    public BigInteger sign(BigInteger blindedMessage) {
        return blindedMessage.multiply(this.privateKey).mod(domainParams.getN());
    }

    // 解盲签名
    public BigInteger unblindSignature(BigInteger blindSignature, BigInteger blindingFactor) {
        return blindSignature.multiply(blindingFactor.modInverse(domainParams.getN())).mod(domainParams.getN());
    }

    // 验证签名
    public boolean verifySignature(String message, BigInteger signature) throws NoSuchAlgorithmException {
        BigInteger hashedMessage = hashMessage(message);

        // 计算 signature * G
        FixedPointCombMultiplier multiplier = new FixedPointCombMultiplier();
        ECPoint leftSide = multiplier.multiply(domainParams.getG(), signature).normalize();

        // 计算 hashedMessage * publicKey
        ECPoint rightSide = multiplier.multiply(publicKey, hashedMessage).normalize();

        return leftSide.equals(rightSide);
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String message = "This is a secret message.";

        // 1. 设置
        BlindSignature signer = new BlindSignature();
        BigInteger blindingFactor = signer.generateBlindingFactor();

        // 2. 盲化消息
        BigInteger blindedMessage = signer.blindMessage(message, blindingFactor);

        // 3. 签名
        BigInteger blindSignature = signer.sign(blindedMessage);

        // 4. 解盲
        BigInteger signature = signer.unblindSignature(blindSignature, blindingFactor);

        // 5. 验证
        boolean isValid = signer.verifySignature(message, signature);

        System.out.println("原始消息: " + message);
        System.out.println("盲化因子: " + blindingFactor);
        System.out.println("盲化消息: " + blindedMessage);
        System.out.println("盲签名: " + blindSignature);
        System.out.println("解盲签名: " + signature);
        System.out.println("签名是否有效: " + isValid);

        if (isValid) {
            System.out.println("签名验证成功!");
        } else {
            System.out.println("签名验证失败!");
        }
    }
}
