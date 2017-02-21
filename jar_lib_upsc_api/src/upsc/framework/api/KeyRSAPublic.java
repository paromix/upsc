package upsc.framework.api;

/**
 * The public class of RSA public key. 
 */
public class KeyRSAPublic extends KeyRSAPair {
	private byte[] m_KeyValue = null;

	/**
	 * Constructor of {@link KeyRSAPublic}.
	 * @param keyValue Value of RSA public key.
	 */
	public KeyRSAPublic(byte[] keyValue){
		m_KeyValue = new byte[keyValue.length];
		System.arraycopy(keyValue, 0, m_KeyValue, 0, keyValue.length);
	}
	
	/**
	 * Get byte size of RSA public key.
	 * @return size of RSA public key.
	 */
	public byte[] getBytes(){
		return m_KeyValue;
	}
}
