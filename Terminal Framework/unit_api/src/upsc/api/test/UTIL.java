package upsc.api.test;

class UTIL {
	static String toHex(byte[] a) {
	    StringBuilder sb = new StringBuilder();
	    for(final byte b: a)
	        sb.append(String.format("%02x ", b&0xff));
	    return sb.toString();
	}
}
