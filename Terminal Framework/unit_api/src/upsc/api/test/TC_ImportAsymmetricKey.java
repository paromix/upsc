package upsc.api.test;

import java.util.Arrays;

import android.util.Log;
import upsc.framework.api.KeyLengthAsymmetric;
import upsc.framework.api.KeyLengthSymmetric;
import upsc.framework.api.KeyRSAPair;
import upsc.framework.api.KeyRSAPrivateDecoded;
import upsc.framework.api.KeyRSAPrivateEncoded;
import upsc.framework.api.KeySymmetricDecoded;
import upsc.framework.api.KeySymmetricEncoded;
import upsc.framework.api.UPSCException;
import upsc.framework.api.UpscSIM;

public class TC_ImportAsymmetricKey extends UPSCTestCase {
	
	private static final String LOG_TAG = "TC_ImportAsymmetricKey";
	
	public void testExportAsymmetricKeySimple() throws Exception{
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
		
		KeyRSAPrivateDecoded decodedKey = m_upsc.exportAsymmetricKey(key.getPrivateKey(), keyPIN);
		if( decodedKey == null ){
			fail("Key Export Fails");
		}else if( decodedKey.getBytes() == null ){
			fail("Key Export Fails");
		}
		
		KeyRSAPrivateEncoded importedKey = m_upsc.importAsymmetricKey(decodedKey, keyPIN);
		if( importedKey == null ){
			fail("Key Import Fails");
		}else if( importedKey.getBytes() == null ){
			fail("Key Import Fails");
		}else if( !Arrays.equals(key.getPrivateKey().getBytes(), importedKey.getBytes()) ){
			fail("Key Import Fails");
		}

	}
}
