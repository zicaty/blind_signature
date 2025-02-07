package com.example;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

public class ECCBlindSignature {
    private static final ECDomainParameters CURVE;
    private static final BigInteger ORDER;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters params = CustomNamedCurves.getByName("secp256k1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        ORDER = CURVE.getN();
    }

    public static class KeyPair {
        public final BigInteger privateKey;
        public final ECPoint publicKey;

        public KeyPair(BigInteger privateKey, ECPoint publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }

    public static class BlindingResult {
        public final ECPoint blindedMessage;
        public final BigInteger blindingFactor;

        public BlindingResult(ECPoint blindedMessage, BigInteger blindingFactor) {
            this.blindedMessage = blindedMessage;
            this.blindingFactor = blindingFactor;
        }
    }

    public static KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(ORDER.bitLength(), random);
        } while (privateKey.compareTo(ORDER) >= 0 || privateKey.equals(BigInteger.ZERO));

        ECPoint publicKey = CURVE.getG().multiply(privateKey);
        return new KeyPair(privateKey, publicKey);
    }

    public static BlindingResult blind(byte[] message, ECPoint publicKey) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        BigInteger m = new BigInteger(1, hash.digest(message));
        
        // Calculate H(m)G
        ECPoint mG = CURVE.getG().multiply(m);
        
        // Generate random blinding factor
        SecureRandom random = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(ORDER.bitLength(), random);
        } while (r.compareTo(ORDER) >= 0 || r.equals(BigInteger.ZERO));
        
        // Calculate rQ
        ECPoint rQ = publicKey.multiply(r);
        
        // m' = H(m)G + rQ
        ECPoint mPrime = mG.add(rQ);
        
        return new BlindingResult(mPrime, r);
    }

    public static ECPoint sign(ECPoint blindedMessage, BigInteger privateKey) {
        return blindedMessage.multiply(privateKey);
    }

    public static ECPoint unblind(ECPoint blindSignature, BigInteger blindingFactor) {
        return blindSignature.subtract(CURVE.getG().multiply(blindingFactor));
    }

    public static boolean verify(byte[] message, ECPoint signature, ECPoint publicKey) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        BigInteger m = new BigInteger(1, hash.digest(message));
        
        // Calculate H(m)Q
        ECPoint mQ = publicKey.multiply(m);
        
        return signature.equals(mQ);
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = generateKeyPair();
            String message = "Hello, World!";
            
            BlindingResult blindingResult = blind(message.getBytes(), keyPair.publicKey);
            ECPoint blindSignature = sign(blindingResult.blindedMessage, keyPair.privateKey);
            ECPoint signature = unblind(blindSignature, blindingResult.blindingFactor);
            
            boolean isValid = verify(message.getBytes(), signature, keyPair.publicKey);
            System.out.println("Signature valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}