package upsc.api.test;

import android.util.Log;
import upsc.framework.api.KeyLengthAsymmetric;
import upsc.framework.api.KeyLengthSymmetric;
import upsc.framework.api.KeyRSAPair;
import upsc.framework.api.KeySymmetricEncoded;
import upsc.framework.api.UpscSIM;

public class TC_CreateAsymmetricKey extends UPSCTestCase {
	
	private static final String LOG_TAG = "TC_CreateAsymmetricKey";
	
	public void testCreateAsymmetricKeySimple() throws Exception{
		KeyRSAPair key = m_upsc.createAsymmetricKey(
												KeyLengthAsymmetric.RSA_1024, 
												null
												);
		if( key == null ){
			fail("Key Creation Fails");
		}else if( key.getBytes() == null ){
			fail("Key Creation Fails");
		}
		
		String pubKey = UTIL.toHex(key.getPublicKey().getBytes());
		String prvKey = UTIL.toHex(key.getPrivateKey().getBytes());
		
		Log.i(LOG_TAG, "prvKey : " + prvKey);
		Log.i(LOG_TAG, "pubKey : " + pubKey);
	}
	
	public void testCreateAsymmetricKeySimplewithPIN() throws Exception{
		byte[] keyPIN = {0x01, 0x02, 0x03, 0x04};
		KeyRSAPair key = m_upsc.createAsymmetricKey(
												KeyLengthAsymmetric.RSA_1024, 
												keyPIN
												);
		if( key == null ){
			fail("Key Creation Fails");
		}else if( key.getBytes() == null ){
			fail("Key Creation Fails");
		}
		
		String pubKey = UTIL.toHex(key.getPublicKey().getBytes());
		String prvKey = UTIL.toHex(key.getPrivateKey().getBytes());
		
		Log.i(LOG_TAG, "prvKey : " + prvKey);
		Log.i(LOG_TAG, "pubKey : " + pubKey);
	}

}
