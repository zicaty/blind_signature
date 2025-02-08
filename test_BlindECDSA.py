from fastecdsa import curve, ecdsa, keys
import BlindECDSA

def test_blind_signature():
    # Initialize
    ecdsa = BlindECDSA()
    
    # Generate signer's keypair
    private_key, public_key = ecdsa.generate_keypair()
    
    # Message to be signed
    message = b"Hello, World!"
    
    # User: Blind the message
    m_prime, alpha, beta, R_prime = ecdsa.blind_message(message, public_key)
    
    # Signer: Sign the blinded message
    s_prime = ecdsa.sign_blinded(m_prime, private_key)
    
    # User: Unblind the signature
    r, s = ecdsa.unblind_signature(s_prime, alpha, beta, R_prime)
    
    # Verify the signature
    assert ecdsa.verify(message, (r, s), public_key)
    print("Blind signature test passed!")

if __name__ == "__main__":
    test_blind_signature()