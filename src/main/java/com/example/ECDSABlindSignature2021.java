package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

public class ECDSABlindSignature2021 {

    private static final SecureRandom secureRandom = new SecureRandom();

    // Elliptic Curve parameters
    private static final String CURVE_NAME = "secp256r1";
    private static final ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
    private static final BigInteger n = ecSpec.getN(); // Order of the elliptic curve
    private static final ECPoint G = ecSpec.getG(); // Base point
    private static final BigInteger p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16); // Prime

    // Helper function to generate random BigInteger
    private static BigInteger generateRandomBigInteger() {
        return new BigInteger(n.bitLength(), secureRandom);
    }

    // Blinding
    public static class BlindedMessage {
        public final BigInteger blindedMessage;
        public final BigInteger blindingFactor;

        public BlindedMessage(BigInteger blindedMessage, BigInteger blindingFactor) {
            this.blindedMessage = blindedMessage;
            this.blindingFactor = blindingFactor;
        }
    }

    // 1. Blind Message
    public static BlindedMessage blindMessage(BigInteger message) {
        BigInteger r = generateRandomBigInteger(); // Blinding factor
        BigInteger messageBlinded = message.multiply(r).mod(n); // Blind the message
        return new BlindedMessage(messageBlinded, r);
    }

    // 2. Sign Blinded Message
    public static BigInteger signBlindedMessage(BigInteger blindedMessage, BigInteger privateKey) {
        return blindedMessage.multiply(privateKey).mod(n);
    }

    // 3. Unblind Signature
    public static BigInteger unblindSignature(BigInteger blindedSignature, BigInteger blindingFactor) {
        return blindedSignature.multiply(blindingFactor.modInverse(n)).mod(n);
    }

    // 4. Verify Signature
    public static boolean verifySignature(BigInteger message, BigInteger signature, BigInteger publicKey) {
        BigInteger left = signature.multiply(G.getAffineXCoord().toBigInteger()).mod(n);
        BigInteger right = message.multiply(publicKey).mod(n);
        return left.equals(right);
    }

    public static void main(String[] args) {
        try {
            // 1. Setup: Generate key pair
            BigInteger privateKey = generateRandomBigInteger();
            BigInteger publicKey = G.multiply(privateKey).getAffineXCoord().toBigInteger().mod(n);

            // 2. The message to be signed
            BigInteger message = new BigInteger("1234567890");

            // 3. Blind the message
            BlindedMessage blindedMessage = blindMessage(message);

            // 4. Sign the blinded message
            BigInteger blindedSignature = signBlindedMessage(blindedMessage.blindedMessage, privateKey);

            // 5. Unblind the signature
            BigInteger signature = unblindSignature(blindedSignature, blindedMessage.blindingFactor);

            // 6. Verify the signature
            boolean isValid = verifySignature(message, signature, publicKey);

            System.out.println("Signature is valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
