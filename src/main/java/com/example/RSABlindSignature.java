package com.example;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RSABlindSignature {
    static PublicKey publicKey;
    static PrivateKey privateKey;
    static BigInteger n, e, d;

    static void init() throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        n = pubKeySpec.getModulus();
        e = pubKeySpec.getPublicExponent();
        RSAPrivateKeySpec privKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        d = privKeySpec.getPrivateExponent();
    }

    public static void main(String[] args) throws Exception {
        init();
        // Message to be signed
        String message = "Hello, this is a secret message.";
        byte[] messageBytes = message.getBytes();

        // Hash the message
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(messageBytes);
        BigInteger m = new BigInteger(1, hash);

        // Blinding
        SecureRandom random = new SecureRandom();
        BigInteger r = new BigInteger(n.bitLength() - 1, random).mod(n);
        BigInteger rPowE = r.modPow(e, n);
        BigInteger blindedMessage = m.multiply(rPowE).mod(n);

        // Signing the blinded message using raw RSA signature
        BigInteger blindedSignature = signWithPrivateKey(blindedMessage);

        // Unblinding
        BigInteger rInv = r.modInverse(n);
        BigInteger signature = blindedSignature.multiply(rInv).mod(n);

        // Verification
        BigInteger verification = signature.modPow(e, n);
        boolean isValid = verification.equals(m);

        System.out.println("Signature valid: " + isValid);
    }

    private static BigInteger signWithPrivateKey(BigInteger blindedMessage) throws Exception {
        return blindedMessage.modPow(d, n);
    }
}