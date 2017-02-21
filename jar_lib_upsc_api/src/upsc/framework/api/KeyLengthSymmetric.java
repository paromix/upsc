package upsc.framework.api;

/**
 * The public enum class of symmetric key Length management. 
 */
public enum KeyLengthSymmetric {
	DES_56(56),			DES_112(112), 		DES_168(168),
	AES_128(128), 		AES_192(192), 		AES_256(256),
	GENERIC_128(128), 	GENERIC_168(168), 	GENERIC_192(192), GENERIC_256(256);
	
	private int length;
	
	KeyLengthSymmetric(int bits){
		length = bits/8;
	}
	
	/**
	 * Get byte size of symmetric Key.
	 * @return size of symmetric Key.
	 */
	public int getByteSize(){
		return length;
	}
}
