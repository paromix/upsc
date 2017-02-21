package upsc.framework.api;

/**
 * The public class of decoded symmetric key. 
 */
public class KeySymmetricDecoded extends KeySymmetric {

	private byte[] m_PlainKeyValue = null;
	private KeyLengthSymmetric m_KeyLen;
	
	/**
	 * The public constructor of {@link KeySymmetricEncoded}. 
	 * @param keyValue Value of plain key
	 * @param keyLen Bit length of the key
	 */
	public KeySymmetricDecoded(byte[] keyValue, KeyLengthSymmetric keyLen) {
		m_PlainKeyValue = new byte[keyValue.length];
		System.arraycopy(keyValue, 0, m_PlainKeyValue, 0, keyValue.length);
		m_KeyLen = keyLen;
	}

	/**
	 * Get byte array of key value.
	 * @return byte array of key value.
	 */
	public byte[] getBytes(){
		return m_PlainKeyValue;
	}
	
	/**
	 * Get bit length of the key.
	 * @return bit length of the key.
	 */
	public KeyLengthSymmetric getKeyLength(){
		return m_KeyLen;
	}
}
