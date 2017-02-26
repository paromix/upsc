package upsc.framework.api;

/**
 * The public class of RSA key management.
 */
public class KeyRSAPair extends Key {
	private byte[] m_EncKeyValue = null;
	private KeyRSAPrivateEncoded m_prvKey = null;
	private KeyRSAPublic m_pubKey = null;
	
	KeyRSAPair(){
	}
	
	/**
	 * Set private and public key to encrypt.
	 * @param prvKey Private key for RSA. 
	 * @param pubKey Public key for RSA.
	 */
	public KeyRSAPair(byte[] prvKey, byte[] pubKey){
		m_prvKey = new KeyRSAPrivateEncoded(prvKey);
		m_pubKey = new KeyRSAPublic(pubKey);
		m_EncKeyValue = new byte[prvKey.length + pubKey.length];
		System.arraycopy(prvKey, 0, m_EncKeyValue, 0, prvKey.length);
		System.arraycopy(pubKey, 0, m_EncKeyValue, prvKey.length, pubKey.length);
	}

	/**
	 * Get byte size of key value to encrypt.
	 * @return size of key value to encrypt.
	 */
	public byte[] getBytes(){
		return m_EncKeyValue;
	}
	
	/**
	 * Get byte size of private key value.
	 * @return size of private key value.
	 */
	public KeyRSAPrivateEncoded getPrivateKey(){
		return m_prvKey;
	}
	
	/**
	 * Get byte size of public key value.
	 * @return size of public key value.
	 */
	public KeyRSAPublic getPublicKey(){
		return m_pubKey;
	}
}
