package com.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import kl.hsm.server.svc.base.SvcBase;
import kl.hsm.server.svc.base.HashAlgoParam;
import kl.hsm.server.svc.base.Algo;
import kl.hsm.server.svc.base.SvcException;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Security;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class SM2BlindSignatureDemo {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Initialize HSM client
        TTransport transport = new TSocket("10.4.64.68", 10000);
        transport.open();
        TProtocol protocol = new TBinaryProtocol(transport);
        SvcBase.Client hsmClient = new SvcBase.Client(protocol);
        
        // Initialize SM2 parameters using named curve
        X9ECParameters sm2Parameters = ECUtil.getNamedCurveByName("sm2p256v1");
        ECDomainParameters domainParams = new ECDomainParameters(
            sm2Parameters.getCurve(),
            sm2Parameters.getG(),
            sm2Parameters.getN(),
            sm2Parameters.getH()
        );
        
        // Generate key pair
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.init(new ECKeyGenerationParameters(domainParams, new java.security.SecureRandom()));
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Message to sign
        String message = "This is a test message for blind signature";
        byte[] messageBytes = message.getBytes();
        
        // Hash message using SM3
        org.bouncycastle.crypto.digests.SM3Digest sm3 = new org.bouncycastle.crypto.digests.SM3Digest();
        sm3.update(messageBytes, 0, messageBytes.length);
        byte[] hash = new byte[sm3.getDigestSize()];
        sm3.doFinal(hash, 0);
        
        // Generate blinding factor
        ECMultiplier multiplier = new FixedPointCombMultiplier();
        BigInteger k = new BigInteger(256, new java.security.SecureRandom());
        ECPoint rPoint = multiplier.multiply(sm2Parameters.getG(), k);
        BigInteger r = rPoint.normalize().getAffineXCoord().toBigInteger().mod(sm2Parameters.getN());
        
        // Blind the message
        BigInteger e = new BigInteger(1, hash);
        BigInteger rInv = r.modInverse(sm2Parameters.getN());
        BigInteger blindedMessage = e.multiply(rInv).mod(sm2Parameters.getN());
        
        // Convert blinded message to fixed-length byte array
        byte[] blindedMessageBytes = toFixedLengthByteArray(blindedMessage, 32);
        
        // Create blind signature using HSM
        long sessionId = 0;
        int keyIndex = 110; // HSM key index
        HashAlgoParam hashParam = new HashAlgoParam();
        byte[] blindSignature = null;
        
        try {
            System.out.println("Opening HSM session...");
            sessionId = hsmClient.openSession();
            System.out.println("HSM session opened with ID: " + sessionId);
            
            System.out.println("Using key index: " + keyIndex);
            hashParam.setHashAlgo(Algo.SM3);
            System.out.println("Using SM3 hash algorithm");
            
            // Get private key access rights
            System.out.println("Authenticating with HSM...");
            hsmClient.getPrivateKeyAccessRight(sessionId, keyIndex, ByteBuffer.wrap("pass".getBytes()));
            System.out.println("Authentication successful");
            
            System.out.println("Sending blinded message for signing...");
            blindSignature = hsmClient.signIn(sessionId, keyIndex, ByteBuffer.wrap(blindedMessageBytes), hashParam).array();
            hsmClient.releasePrivateKeyAccessRight(sessionId, keyIndex);
            System.out.println("Blind signature received (hex): " + bytesToHex(blindSignature));
            System.out.println("Blind signature length: " + blindSignature.length + " bytes");
            System.out.println("Received blind signature from HSM");
        } catch (SvcException ex) {
            System.err.println("HSM operation failed: " + ex.getMessage());
            ex.printStackTrace();
            return;
        } catch (TException ex) {
            System.err.println("HSM communication error: " + ex.getMessage());
            ex.printStackTrace();
            return;
        }
        
        // Unblind the signature (HSM returns raw (r,s) pair)
        BigInteger[] sigComponents = decodeHSMSignature(blindSignature);
        BigInteger rPrime = sigComponents[0];
        BigInteger sPrime = sigComponents[1];
        
        // Reconstruct original r component
        BigInteger rOriginal = rPrime.multiply(rInv).mod(sm2Parameters.getN());
        
        // Unblind s component
        BigInteger unblindedS = sPrime.multiply(rInv).mod(sm2Parameters.getN());
        
        // Verify rOriginal is valid
        if (rOriginal.compareTo(BigInteger.ZERO) <= 0 || rOriginal.compareTo(sm2Parameters.getN()) >= 0) {
            throw new IllegalStateException("Invalid r component in signature");
        }
        
        // Verify unblindedS is valid
        if (unblindedS.compareTo(BigInteger.ZERO) <= 0 || unblindedS.compareTo(sm2Parameters.getN()) >= 0) {
            throw new IllegalStateException("Invalid s component in signature");
        }
        
        // Reconstruct signature
        byte[] signature = encodeSignature(rOriginal, unblindedS);
        
        // Debug signature bytes
        System.out.println("Encoded signature bytes: " + bytesToHex(signature));
        BigInteger[] decodedSig = decodeHSMSignature(signature);
        System.out.println("Decoded signature (r, s): " + decodedSig[0].toString(16) + ", " + decodedSig[1].toString(16));
        
        // Debug output
        System.out.println("Original message hash: " + bytesToHex(hash));
        System.out.println("Blinded message: " + blindedMessage.toString(16));
        System.out.println("Blind signature (r', s'): " + rPrime.toString(16) + ", " + sPrime.toString(16));
        System.out.println("Unblinded signature (r, s): " + rOriginal.toString(16) + ", " + unblindedS.toString(16));
        System.out.println("Final signature: " + bytesToHex(signature));
        
        // Verify signature using HSM
        boolean verified = hsmClient.verifyIn(keyIndex, ByteBuffer.wrap(hash), hashParam, ByteBuffer.wrap(signature));
        
        System.out.println("Message: " + message);
        System.out.println("Signature verified: " + verified);
        
        // Clean up
        hsmClient.closeSession(sessionId);
        transport.close();
    }
    
    private static BigInteger[] decodeHSMSignature(byte[] signature) {
        // HSM returns ASN.1 DER encoded signature
        try {
            ASN1InputStream asn1InputStream = new ASN1InputStream(signature);
            ASN1Sequence seq = (ASN1Sequence)asn1InputStream.readObject();
            BigInteger r = ((ASN1Integer)seq.getObjectAt(0)).getPositiveValue();
            BigInteger s = ((ASN1Integer)seq.getObjectAt(1)).getPositiveValue();
            return new BigInteger[] { r, s };
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid ASN.1 encoded signature", e);
        }
    }
    
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static BigInteger[] decodeSignature(byte[] signature) {
        
        if (signature.length != 64) {
            throw new IllegalArgumentException("Invalid signature length");
        }
        
        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];
        System.arraycopy(signature, 0, rBytes, 0, 32);
        System.arraycopy(signature, 32, sBytes, 0, 32);
        
        return new BigInteger[] {
            new BigInteger(1, rBytes),
            new BigInteger(1, sBytes)
        };
    }

    private static byte[] encodeSignature(BigInteger r, BigInteger s) {
        try {
            // Create ASN.1 sequence with r and s components
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            
            // Create DER sequence and encode
            DERSequence seq = new DERSequence(v);
            return seq.getEncoded("DER");
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode ASN.1 signature", e);
        }
    }

    private static byte[] toUnsignedByteArray(BigInteger value) {
        byte[] signed = value.toByteArray();
        if (signed[0] != 0) {
            return signed;
        }
        byte[] unsigned = new byte[signed.length - 1];
        System.arraycopy(signed, 1, unsigned, 0, unsigned.length);
        return unsigned;
    }

    private static byte[] toFixedLengthByteArray(BigInteger value, int length) {
        byte[] bytes = new byte[length];
        byte[] biBytes = value.toByteArray();
        int start = (biBytes.length > length) ? biBytes.length - length : 0;
        int copyLength = Math.min(biBytes.length, length);
        System.arraycopy(biBytes, start, bytes, length - copyLength, copyLength);
        return bytes;
    }
}
