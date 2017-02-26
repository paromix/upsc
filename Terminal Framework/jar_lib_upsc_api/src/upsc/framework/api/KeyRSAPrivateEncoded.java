package upsc.framework.api;

/**
 * The public class of encoded RSA private key. 
 */
public class KeyRSAPrivateEncoded extends KeyRSAPair {
	private byte[] m_EncKeyValue = null;

	/**
	 * Constructor of {@link KeyRSAPrivateEncoded}.
	 * @param keyValue Value of key to encrypt.
	 */
	public KeyRSAPrivateEncoded(byte[] keyValue){
		m_EncKeyValue = new byte[keyValue.length];
		System.arraycopy(keyValue, 0, m_EncKeyValue, 0, keyValue.length);
	}
	
	/**
	 * Get byte size of value of key to encrypt
	 * @return byte size of value of key to encrypt.
	 */
	public byte[] getBytes(){
		return m_EncKeyValue;
	}
}
