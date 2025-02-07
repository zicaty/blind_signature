// 使用DeepSeek r1生成的代码。由于cline没有集成这个，所以在浏览器上生成拷贝过来。不能直接运行，需要修改一下。
// 不能验签。
package com.example;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class SM2BlindSignature_DSr1 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Generate SM2 key pair
        KeyPair keyPair = generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        // Message to sign
        byte[] message = "Blind Signature Test".getBytes();

        // User blinds the message
        BlindResult blindResult = blindMessage(message, publicKey);

        // Signer signs the blinded message
        BigInteger[] blindedSig = signBlinded(blindResult.blindedHash, privateKey);

        // User unblinds the signature
        BigInteger[] signature = unblindSignature(blindedSig, blindResult);

        // Verify the signature
        boolean isValid = verifySignature(message, signature, publicKey);
        System.out.println("Signature valid: " + isValid);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("sm2p256v1"), new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static class BlindResult {
        BigInteger blindedHash;
        BigInteger alpha;
        BigInteger beta;
        BigInteger n;

        BlindResult(BigInteger blindedHash, BigInteger alpha, BigInteger beta, BigInteger n) {
            this.blindedHash = blindedHash;
            this.alpha = alpha;
            this.beta = beta;
            this.n = n;
        }
    }

    private static BlindResult blindMessage(byte[] message, ECPublicKey publicKey) {
        ECParameterSpec params = publicKey.getParameters();
        BigInteger n = params.getN();
        BigInteger alpha = new BigInteger(n.bitLength(), new SecureRandom()).mod(n);
        BigInteger beta = new BigInteger(n.bitLength(), new SecureRandom()).mod(n);
        BigInteger e = hashMessage(message, publicKey);
        BigInteger blindedHash = alpha.multiply(e).add(beta).mod(n);
        return new BlindResult(blindedHash, alpha, beta, n);
    }

    private static BigInteger hashMessage(byte[] message, ECPublicKey publicKey) {
        SM3Digest digest = new SM3Digest();
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(message, 0, message.length);
        digest.doFinal(hash, 0);
        return new BigInteger(1, hash);
    }

    private static BigInteger[] signBlinded(BigInteger blindedHash, ECPrivateKey privateKey) {
        SM2Signer signer = new SM2Signer();
        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(privateKey.getD(),
                new ECDomainParameters(privateKey.getParameters().getCurve(),
                        privateKey.getParameters().getG(),
                        privateKey.getParameters().getN()));
        signer.init(true, new ParametersWithRandom(privParams, new SecureRandom()));
        signer.update(blindedHash.toByteArray(), 0, blindedHash.toByteArray().length);
        
        byte[] sig= null;
        try {
            sig = signer.generateSignature();
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        int half = sig.length / 2;
        BigInteger r = new BigInteger(1, sig, 0, half);
        BigInteger s = new BigInteger(1, sig, half, half);
        return new BigInteger[]{r, s};
    }

    private static BigInteger[] unblindSignature(BigInteger[] blindedSig, BlindResult blind) {
        BigInteger n = blind.n;
        BigInteger alphaInv = blind.alpha.modInverse(n);
        BigInteger r = blindedSig[0].subtract(blind.beta).multiply(alphaInv).mod(n);
        BigInteger s = blindedSig[1].multiply(alphaInv).mod(n);
        return new BigInteger[]{r, s};
    }

    private static boolean verifySignature(byte[] message, BigInteger[] sig, ECPublicKey publicKey) {
        SM2Signer verifier = new SM2Signer();
        ECPublicKeyParameters pubParams = new ECPublicKeyParameters(publicKey.getQ(),
                new ECDomainParameters(publicKey.getParameters().getCurve(),
                        publicKey.getParameters().getG(),
                        publicKey.getParameters().getN()));
        verifier.init(false, pubParams);
        verifier.update(message, 0, message.length);
        byte[] rBytes = BigIntegers.asUnsignedByteArray(sig[0]);
        byte[] sBytes = BigIntegers.asUnsignedByteArray(sig[1]);
        byte[] signature = new byte[rBytes.length + sBytes.length];
        System.arraycopy(rBytes, 0, signature, 0, rBytes.length);
        System.arraycopy(sBytes, 0, signature, rBytes.length, sBytes.length);
        return verifier.verifySignature(signature);
    }
}
