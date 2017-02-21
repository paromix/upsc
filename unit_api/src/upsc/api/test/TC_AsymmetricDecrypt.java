package upsc.api.test;

import java.util.Arrays;

import android.util.Log;
import upsc.framework.api.CipherText;
import upsc.framework.api.KeyLengthAsymmetric;
import upsc.framework.api.KeyRSAPair;

public class TC_AsymmetricDecrypt extends UPSCTestCase {
	private static final String LOG_TAG = "TC_AsymmetricDecrypt";

	byte[] m_keyPIN = {0x23, 0x23, 0x23, 0x23};
	KeyRSAPair m_keyPair = null;
	
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

	public void testAsymmetricDecryptSimple() throws Exception{
		byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		CipherText encryptedData = m_upsc.encrypt(m_keyPair.getPublicKey(), data);
		
		if( encryptedData == null ){
			fail("Sign Fails");
		}
		
		Log.i(LOG_TAG, "encryptedData : " + UTIL.toHex(encryptedData.getBytes()));
		
		byte[] decData = m_upsc.decrypt(m_keyPair.getPrivateKey(), m_keyPIN, encryptedData);
		if( decData == null ){
			fail("Decrypt Fails");
		}else if( !Arrays.equals(decData, data) ){
			fail("Decrypt Value Fails");
		}
	}

}
