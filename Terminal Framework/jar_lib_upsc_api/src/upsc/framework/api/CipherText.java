package upsc.framework.api;

/**
 * The public class of CipherText. 
 */
public class CipherText {
	private byte[] m_EncValue = null;
	
	/**
	 * Constructor of {@link CipherText}.	
	 * @param keyValue Value of key to encrypt.
	 */
	public CipherText(byte[] keyValue){
		m_EncValue = new byte[keyValue.length];
		System.arraycopy(keyValue, 0, m_EncValue, 0, keyValue.length);
	}

	/**
	 * Get byte size of value to encrypt.
	 * @return size of value to encrypt.
	 */
	public byte[] getBytes(){
		return m_EncValue;
	}

}
