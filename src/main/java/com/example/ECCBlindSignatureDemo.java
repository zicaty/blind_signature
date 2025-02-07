// created by deepseek, without deepthink r1 and online
package com.example;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

public class ECCBlindSignatureDemo {

    static ECDomainParameters domainParams=null;
    static BigInteger n;
    
    public static void main(String[] args) {
        // Add BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters params = CustomNamedCurves.getByName("secp256k1");


        ECCurve curve = new SecP256K1Curve();
        n = curve.getOrder(); // Curve order
        final ECPoint G = params.getG(); // Base point
        domainParams = new ECDomainParameters(curve, G, n);

        // Step 1: Generate signer's key pair
        BigInteger privateKey = new BigInteger(256, new SecureRandom()).mod(n);
        ECPoint publicKey = G.multiply(privateKey);

        // Step 2: Message to be signed
        String message = "Hello, ECC Blind Signature!";
        BigInteger messageHash = hashMessage(message);

        // Step 3: Blind the message
        BigInteger blindingFactor = new BigInteger(256, new SecureRandom()).mod(n);
        BigInteger blindedMessageHash = messageHash.multiply(blindingFactor).mod(n);

        // Step 4: Sign the blinded message
        BigInteger[] blindedSignature = signBlindedMessage(blindedMessageHash, privateKey);

        // Step 5: Unblind the signature
        BigInteger[] unblindedSignature = unblindSignature(blindedSignature, blindingFactor);

        // Step 6: Verify the signature
        boolean isValid = verifySignature(messageHash, unblindedSignature, publicKey);
        System.out.println("Signature is valid: " + isValid);
    }

    // Hash the message using SHA-256
    private static BigInteger hashMessage(String message) {
        SHA256Digest digest = new SHA256Digest();
        byte[] messageBytes = message.getBytes();
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(messageBytes, 0, messageBytes.length);
        digest.doFinal(hash, 0);
        return new BigInteger(1, hash);
    }

    // Sign the blinded message
    private static BigInteger[] signBlindedMessage(BigInteger blindedMessageHash, BigInteger privateKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privateKey, domainParams));
        return signer.generateSignature(blindedMessageHash.toByteArray());
    }

    // Unblind the signature
    private static BigInteger[] unblindSignature(BigInteger[] blindedSignature, BigInteger blindingFactor) {
        BigInteger r = blindedSignature[0];
        BigInteger sPrime = blindedSignature[1];
        BigInteger s = sPrime.multiply(blindingFactor.modInverse(n)).mod(n);
        return new BigInteger[]{r, s};
    }

    // Verify the signature
    private static boolean verifySignature(BigInteger messageHash, BigInteger[] signature, ECPoint publicKey) {
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(publicKey, domainParams));
        return verifier.verifySignature(messageHash.toByteArray(), signature[0], signature[1]);
    }
}