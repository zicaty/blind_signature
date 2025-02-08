// use gemini gernerated. 
// study the paper at https://eprint.iacr.org/2021/1449.pdf, write java code to do ecdsa blind signature. and write code to verfity the unblinded signature.

package com.example;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public class BlindECDSASignature {

    private static final String CURVE_NAME = "secp256k1"; // You can change this
    private static final X9ECParameters CURVE = SECNamedCurves.getByName(CURVE_NAME);
    private static final ECDomainParameters EC_PARAMS = new ECDomainParameters(CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH());
    private static final SecureRandom RANDOM = new SecureRandom();

    public static class BlindSignature {
        public ECPoint blindedMessage;
        public BigInteger blindFactor;
    }

    public static class UnblindedSignature {
        public BigInteger r;
        public BigInteger s;
    }


    public static BlindSignature blindMessage(ECPoint message) {
        BigInteger blindFactor = new BigInteger(EC_PARAMS.getN().bitLength(), RANDOM);
        ECPoint blindedMessage = EC_PARAMS.getG().multiply(blindFactor).add(message);

        BlindSignature blindSignature = new BlindSignature();
        blindSignature.blindedMessage = blindedMessage;
        blindSignature.blindFactor = blindFactor;
        return blindSignature;
    }

    public static UnblindedSignature signBlindedMessage(BigInteger privateKey, ECPoint blindedMessage) {
        // In a real application, you would hash the blinded message before signing.
        // For simplicity, we'll sign it directly here.  NEVER DO THIS IN REAL CODE.
        BigInteger e = blindedMessage.getXCoord().toBigInteger(); //  Dummy hash - REPLACE WITH REAL HASHING

        // Sign the blinded message
        BigInteger n = EC_PARAMS.getN();
        BigInteger k = new BigInteger(n.bitLength(), RANDOM); // Ephemeral key
        ECPoint rPoint = EC_PARAMS.getG().multiply(k);
        BigInteger r = rPoint.getXCoord().toBigInteger().mod(n);
        BigInteger s = (k.modInverse(n).multiply((e.add(privateKey.multiply(r)))).mod(n));

        UnblindedSignature unblindedSignature = new UnblindedSignature();
        unblindedSignature.r = r;
        unblindedSignature.s = s;
        return unblindedSignature;
    }

    public static UnblindedSignature unblindSignature(UnblindedSignature blindedSignature, BigInteger blindFactor) {
        BigInteger r = blindedSignature.r;
        BigInteger s = blindedSignature.s;

        BigInteger n = EC_PARAMS.getN();
        BigInteger unblindedS = (s.multiply(blindFactor.modInverse(n))).mod(n);

        UnblindedSignature unblindedSignature = new UnblindedSignature();
        unblindedSignature.r = r;
        unblindedSignature.s = unblindedS;
        return unblindedSignature;
    }

    public static boolean verifyUnblindedSignature(ECPoint message, UnblindedSignature signature, ECPoint publicKey) {
        BigInteger r = signature.r;
        BigInteger s = signature.s;

        BigInteger n = EC_PARAMS.getN();

        if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0 ||
                s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) {
            return false;
        }

        BigInteger e = message.getXCoord().toBigInteger(); // Dummy hash - REPLACE WITH REAL HASHING

        BigInteger w = s.modInverse(n);
        BigInteger u1 = (e.multiply(w)).mod(n);
        BigInteger u2 = (r.multiply(w)).mod(n);

        ECPoint v = EC_PARAMS.getG().multiply(u1).add(publicKey.multiply(u2));
        BigInteger vX = v.getXCoord().toBigInteger().mod(n);

        return vX.equals(r);
    }



    public static void main(String[] args) {
        // Example usage:

        // 1. Generate Key Pair (In real code, use a proper key generation method)
        BigInteger privateKey = new BigInteger(EC_PARAMS.getN().bitLength(), RANDOM);
        ECPoint publicKey = EC_PARAMS.getG().multiply(privateKey);

        // 2. Message to be signed
        ECPoint message = EC_PARAMS.getG().multiply(new BigInteger("5", 16));  // Example message point.  In real code, hash the message and convert to point.

        // 3. Blind the message
        BlindSignature blindSignature = blindMessage(message);

        // 4. Sign the blinded message (done by the signer who has the private key)
        UnblindedSignature blindedSig = signBlindedMessage(privateKey, blindSignature.blindedMessage);

        // 5. Unblind the signature (done by the message owner)
        UnblindedSignature unblindedSignature = unblindSignature(blindedSig, blindSignature.blindFactor);

        // 6. Verify the unblinded signature
        boolean isValid = verifyUnblindedSignature(message, unblindedSignature, publicKey);

        System.out.println("Signature is valid: " + isValid);

    }
}