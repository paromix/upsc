package upsc.api.test;

import android.util.Log;
import upsc.framework.api.KeyLengthAsymmetric;
import upsc.framework.api.KeyRSAPair;
import upsc.framework.api.UpscSIM;

public class TC_AsymmetricVerify extends UPSCTestCase {
	
	private static final String LOG_TAG = "TC_AsymmetricSign";
	
	KeyRSAPair m_keyPair = null;
	byte[] m_keyPIN = {0x01, 0x02, 0x02, 0x01};
	
	public void CreateAsymmetricKey() throws Exception{
		
		m_keyPair = m_upsc.createAsymmetricKey(
												KeyLengthAsymmetric.RSA_1024, 
												m_keyPIN
												);
		if( m_keyPair == null ){
			fail("Key Creation Fails");
		}else if( m_keyPair.getBytes() == null ){
			fail("Key Creation Fails");
		}
	}
	
    @Override
	public void setUp() throws Exception{
    	super.setUp();
    	CreateAsymmetricKey();
	}
	
	@Override
	public void tearDown() throws Exception{
		super.tearDown();
	}
	
	public void testSignVerifySimple() throws Exception{
		byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		byte[] signedData = m_upsc.sign(m_keyPair.getPrivateKey(), m_keyPIN, data);
		
		if( signedData == null ){
			fail("Sign Fails");
		}
		
		Log.i(LOG_TAG, "signedData : " + UTIL.toHex(signedData));
		
		boolean rv = m_upsc.verify(m_keyPair.getPublicKey(), data, signedData);
		if( rv == false ){
			fail("Verify fails");
		}
	}
	
	public void testSignVerifyInvalidData() throws Exception{
		byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		byte[] signedData = m_upsc.sign(m_keyPair.getPrivateKey(), m_keyPIN, data);
		
		if( signedData == null ){
			fail("Sign Fails");
		}
		
		Log.i(LOG_TAG, "signedData : " + UTIL.toHex(signedData));
		
		byte[] invalidData = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
		boolean rv = m_upsc.verify(m_keyPair.getPublicKey(), invalidData, signedData);
		if( rv == true ){
			fail("Verify fails");
		}
	}

}
