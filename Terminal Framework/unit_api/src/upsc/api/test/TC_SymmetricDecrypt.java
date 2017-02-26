package upsc.api.test;

import java.util.Arrays;

import android.util.Log;
import upsc.framework.api.CipherText;
import upsc.framework.api.KeyLengthSymmetric;
import upsc.framework.api.KeySymmetricEncoded;
import upsc.framework.api.UPSCException;

public class TC_SymmetricDecrypt extends UPSCTestCase {
	private static final String LOG_TAG = "TC_SymmetricDecrypt";
	byte[] m_keyPIN = {0x21, 0x21, 0x21, 0x21};
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

	public void testSymmetricDecryptSimple() throws Exception{
		byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		CipherText encryptedData = m_upsc.encrypt(m_Key, m_keyPIN, data);
		
		if( encryptedData == null ){
			fail("Encryption Fails");
		}
		
		Log.i(LOG_TAG, "encryptedData : " + UTIL.toHex(encryptedData.getBytes()));
		
		byte[] decryptedData = m_upsc.decrypt(m_Key, m_keyPIN, encryptedData);
		if( decryptedData == null ){
			fail("Decryption Fails");
		}else if( !Arrays.equals(decryptedData, data) ){
			Log.i(LOG_TAG, "decryptedData : " + UTIL.toHex(decryptedData));
			fail("Decrypted Data is invalid");
		}
	}
	
	public void testSymmetricDecryptWithWrongPIN() throws Exception{
		byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		CipherText encryptedData = m_upsc.encrypt(m_Key, m_keyPIN, data);
		
		if( encryptedData == null ){
			fail("Encryption Fails");
		}
		
		Log.i(LOG_TAG, "encryptedData : " + UTIL.toHex(encryptedData.getBytes()));
		
		byte[] wrongPIN = {0x23, 0x23, 0x23, 0x23};
		try{
			byte[] decryptedData = m_upsc.decrypt(m_Key, wrongPIN, encryptedData);
			fail("Not Reached");
		}catch(UPSCException e){
			// Pass
		}
	}

}
