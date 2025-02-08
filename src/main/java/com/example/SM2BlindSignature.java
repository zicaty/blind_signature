package com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import java.math.BigInteger;
import java.security.*;

public class SM2BlindSignature {
    static PublicKey publicKey;
    static PrivateKey privateKey;
    static ECPoint G, q;
    static BigInteger n, d;

    static void init()
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        // X9ECParameters eccParameters = ECUtil.getNamedCurveByName("sm2p256v1");
        X9ECParameters eccParameters = ECUtil.getNamedCurveByName("secp256k1");
        G = eccParameters.getG();
        n = eccParameters.getN();
        ECParameterSpec ecParameterSpec = new ECParameterSpec(eccParameters.getCurve(), G, eccParameters.getN());

        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ecParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey).getD();
        q = ((org.bouncycastle.jce.interfaces.ECPublicKey) publicKey).getQ();
    }

    byte[] sign(byte[] message, BigInteger d) {
        // generate a random number k
        SecureRandom random = new SecureRandom();
        BigInteger k = new BigInteger(n.bitLength(), random).mod(n);
        // calculate R = [k]G
        ECPoint R = G.multiply(k);
        // calculate s = (1 + dA)^-1 * (k - dA * e) mod n
        BigInteger e = new BigInteger(1, message);
        BigInteger s = k.subtract(d.multiply(e)).mod(n);
        s = s.multiply(d.add(BigInteger.ONE).modInverse(n)).mod(n);
        return s.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        init();
        // Message to be signed
        String message = "Hello, this is a secret message.";
        byte[] messageBytes = message.getBytes();
        // Hash the message
        MessageDigest digest = MessageDigest.getInstance("SHA256", "BC");
        byte[] hash = digest.digest(messageBytes);
        BigInteger m = new BigInteger(1, hash);

        // Blinding, m' = m * rG
        SecureRandom random = new SecureRandom();
        BigInteger r = new BigInteger(n.bitLength(), random).mod(n);
        ECPoint R = G.multiply(r);
        ECPoint m1 = R.multiply(m);

        // Signing the blinded message
        BigInteger s1 = d.multiply(m1.getXCoord().toBigInteger()).mod(n);

        // Unblinding
        BigInteger rInv = r.modInverse(n);
        BigInteger s = s1.multiply(rInv).mod(n);

        // Verification
        ECPoint verificationPoint = G.multiply(s);
        boolean isValid = verificationPoint.equals(q.multiply(m));

        System.out.println("Signature valid: " + isValid);
    }
}