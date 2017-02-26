package upsc.framework.api;
/**
 * The public class of decoded RSA private key. 
 */
public class KeyRSAPrivateDecoded extends KeyRSAPair {
	private byte[] m_PlainKeyValue = null;
	
	/**
	 * The public constructor of {@link KeyRSAPrivateDecoded}. 
	 * @param keyValue Value of plain key
	 */
	public KeyRSAPrivateDecoded(byte[] keyValue) {
		m_PlainKeyValue = new byte[keyValue.length];
		System.arraycopy(keyValue, 0, m_PlainKeyValue, 0, keyValue.length);
	}

	/**
	 * Get byte array of key value.
	 * @return byte array of key value.
	 */
	public byte[] getBytes(){
		return m_PlainKeyValue;
	}

}
