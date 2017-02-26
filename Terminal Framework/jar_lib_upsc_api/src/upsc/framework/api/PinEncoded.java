package upsc.framework.api;

/**
 * The public class of encoded PIN. 
 */
public class PinEncoded extends Pin {
	private byte[] m_EncPIN = null;
	
	/**
	 * The public constructor of {@link PinEncoded}. 
	 * @param PIN encrypted PIN
	 */
	public PinEncoded(byte[] PIN){
		m_EncPIN = new byte[PIN.length];
		System.arraycopy(PIN, 0, m_EncPIN, 0, PIN.length);
	}
	
	/**
	 * Get byte size of PIN
	 * @return size of PIN
	 */
	public byte[] getBytes(){
		return m_EncPIN;
	}
}
