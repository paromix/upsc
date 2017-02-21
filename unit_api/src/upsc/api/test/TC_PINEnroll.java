package upsc.api.test;

import android.util.Log;
import upsc.framework.api.CipherText;
import upsc.framework.api.KeyLengthSymmetric;
import upsc.framework.api.KeySymmetricEncoded;
import upsc.framework.api.PinEncoded;

public class TC_PINEnroll extends UPSCTestCase {
	private static final String LOG_TAG = "TC_PINEnroll";
	byte[] m_keyPIN = {0x20, 0x20, 0x20, 0x20};
	KeySymmetricEncoded m_Key;
	
	public void CreateSymmetricKey() throws Exception{
		m_Key = m_upsc.createSymmetricKey(
										KeyLengthSymmetric.GENERIC_192, 
										m_keyPIN
										);
		if( m_Key == null ){
			fail("Key Creation Fails");
		}else if( m_Key.getBytes() == null ){
			fail("Key Creation Fails");
		}
	}

    @Override
	public void setUp() throws Exception{
    	super.setUp();
    	CreateSymmetricKey();
	}
	
	@Override
	public void tearDown() throws Exception{
		super.tearDown();
	}

	public void testEnrollPinSimple() throws Exception{
		byte[] pin = {0x32, 0x33, 0x34, 0x35};
		PinEncoded enrolledPIN = m_upsc.enrollPin(m_Key, pin);
		
		if( enrolledPIN == null ){
			fail("Sign Fails");
		}
		
		Log.i(LOG_TAG, "enrolledPIN : " + UTIL.toHex(enrolledPIN.getBytes()));
	}
}
