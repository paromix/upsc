package upsc.framework.api;

/**
 * The public class of encoded symmetric key. 
 */
public class KeySymmetricEncoded extends KeySymmetric {
	private byte[] m_EncKeyValue = null;
	private KeyLengthSymmetric m_KeyLen;
	
	/**
	 * The public constructor of {@link KeySymmetricEncoded}. 
	 * @param keyValue Value of encrypted key
	 * @param keyLen Bit length of the key
	 */
	public KeySymmetricEncoded(byte[] keyValue, KeyLengthSymmetric keyLen){
		m_EncKeyValue = new byte[keyValue.length];
		System.arraycopy(keyValue, 0, m_EncKeyValue, 0, keyValue.length);
		m_KeyLen = keyLen;
	}
	
	/**
	 * Get byte array of key value.
	 * @return byte array of key value.
	 */
	public byte[] getBytes(){
		return m_EncKeyValue;
	}
	
	/**
	 * Get bit length of the key.
	 * @return bit length of the key.
	 */
	public KeyLengthSymmetric getKeyLength(){
		return m_KeyLen;
	}
}
