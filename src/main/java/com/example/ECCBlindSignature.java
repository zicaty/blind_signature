package com.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Random;

public class ECCBlindSignature {
    private static final ECDomainParameters CURVE_PARAMS;
    private static final BigInteger CURVE_ORDER;

    static {
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        CURVE_PARAMS = new ECDomainParameters(
                spec.getCurve(),
                spec.getG(),
                spec.getN(),
                spec.getH(),
                spec.getSeed());
        CURVE_ORDER = CURVE_PARAMS.getN();
    }

    public static class KeyPair {
        public final BigInteger privateKey;
        public final ECPoint publicKey;

        public KeyPair(BigInteger privateKey, ECPoint publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }

    public static KeyPair generateKeyPair() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(
                CURVE_PARAMS, new SecureRandom());
        generator.init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

        return new KeyPair(privKey.getD(), pubKey.getQ());
    }

    public static byte[] blindMessage(byte[] message, ECPoint publicKey, BigInteger[] blindingFactor) {
        try {
            // Hash the message
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = digest.digest(message);
            BigInteger m = new BigInteger(1, messageHash);

            // Generate random blinding factor
            BigInteger r = new BigInteger(CURVE_ORDER.bitLength(), new Random());
            ECPoint rQ = publicKey.multiply(r);

            // Compute blinded message: m' = H(m) + rQx mod n
            BigInteger mPrime = m.add(rQ.normalize().getXCoord().toBigInteger()).mod(CURVE_ORDER);

            blindingFactor[0] = r;
            return mPrime.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Blinding failed", e);
        }
    }

    public static byte[] signBlindedMessage(byte[] blindedMessage, BigInteger privateKey) {
        BigInteger mPrime = new BigInteger(1, blindedMessage);
        // s' = m' * d mod n
        BigInteger sPrime = mPrime.multiply(privateKey).mod(CURVE_ORDER);
        return sPrime.toByteArray();
    }

    public static byte[] unblindSignature(byte[] blindedSignature, BigInteger blindingFactor) {
        BigInteger sPrime = new BigInteger(1, blindedSignature);
        // s = s' - r mod n
        BigInteger s = sPrime.subtract(blindingFactor).mod(CURVE_ORDER);
        return s.toByteArray();
    }

    public static boolean verifySignature(byte[] message, byte[] signature, ECPoint publicKey) {
        try {
            // Hash the message
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = digest.digest(message);
            BigInteger m = new BigInteger(1, messageHash);

            // Get signature value
            BigInteger s = new BigInteger(1, signature);

            // Compute s*G
            ECPoint sG = new FixedPointCombMultiplier().multiply(CURVE_PARAMS.getG(), s);

            // Compute H(m)*Q
            ECPoint mQ = publicKey.multiply(m);

            // Verify s*G == H(m)*Q
            return sG.equals(mQ);
        } catch (Exception e) {
            throw new RuntimeException("Verification failed", e);
        }
    }

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPair keyPair = generateKeyPair();
            System.out.println("Generated key pair");

            // Original message
            String message = "This is a test message";
            System.out.println("Original message: " + message);

            // Blind the message
            BigInteger[] blindingFactor = new BigInteger[1];
            byte[] blindedMessage = blindMessage(message.getBytes(), keyPair.publicKey, blindingFactor);
            System.out.println("Blinded message created");

            // Sign the blinded message
            byte[] blindedSignature = signBlindedMessage(blindedMessage, keyPair.privateKey);
            System.out.println("Blinded message signed");

            // Unblind the signature
            byte[] signature = unblindSignature(blindedSignature, blindingFactor[0]);
            System.out.println("Signature unblinded");

            // Verify the signature
            boolean isValid = verifySignature(message.getBytes(), signature, keyPair.publicKey);
            System.out.println("Signature verification result: " + isValid);

            if (!isValid) {
                throw new RuntimeException("Signature verification failed!");
            }

            System.out.println("Blind signature process completed successfully");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
