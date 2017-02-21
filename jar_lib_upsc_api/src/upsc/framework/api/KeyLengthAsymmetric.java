package upsc.framework.api;

/**
 * The public enum class of asymmetric key Length management. 
 */
public enum KeyLengthAsymmetric {
	RSA_1024(1024), RSA_2048(2048);
	
	private int length;
	
	KeyLengthAsymmetric(int bits){
		length = bits/8;
	}
	
	/**
	 * Get byte size of asymmetric Key.
	 * @return size of asymmetric Key.
	 */
	public int getByteSize(){
		return length;
	}
}
