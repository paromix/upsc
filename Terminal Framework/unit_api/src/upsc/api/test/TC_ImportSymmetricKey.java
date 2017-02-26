package upsc.api.test;

import java.util.Arrays;

import android.util.Log;
import upsc.framework.api.Information;
import upsc.framework.api.KeyLengthSymmetric;
import upsc.framework.api.KeySymmetricDecoded;
import upsc.framework.api.KeySymmetricEncoded;
import upsc.framework.api.UPSCException;
import upsc.framework.api.UpscSIM;

public class TC_ImportSymmetricKey extends UPSCTestCase {
	public void testImportSymmetricKey192() throws Exception{
		byte[] keyPIN = {0x01, 0x02, 0x03, 0x04};
		KeySymmetricEncoded keyCode = m_upsc.createSymmetricKey(
												KeyLengthSymmetric.GENERIC_192, 
												keyPIN
												);
		if( keyCode == null ){
			fail("Key Creation Fails");
		}else if( keyCode.getBytes() == null ){
			fail("Key Creation Fails");
		}
		
		KeySymmetricDecoded decodedKey = m_upsc.exportSymmetricKey(keyCode, keyPIN);
		if( decodedKey == null ){
			fail("Key Export Fails");
		}else if( decodedKey.getBytes() == null ){
			fail("Key Export Fails");
		}
		
		KeySymmetricEncoded importedKey = m_upsc.importSymmetricKey(decodedKey, keyPIN);
		if( importedKey == null ){
			fail("Key Import Fails");
		}else if( importedKey.getBytes() == null ){
			fail("Key Import Fails");
		}else if( !Arrays.equals(importedKey.getBytes(), keyCode.getBytes()) ){
			fail("Key Import Fails");
		}
	}

	public void testImportSymmetricKey256() throws Exception{
		byte[] keyPIN = {0x01, 0x02, 0x03, 0x04};
		KeySymmetricEncoded keyCode = m_upsc.createSymmetricKey(
												KeyLengthSymmetric.GENERIC_256, 
												keyPIN
												);
		if( keyCode == null ){
			fail("Key Creation Fails");
		}else if( keyCode.getBytes() == null ){
			fail("Key Creation Fails");
		}
		
		KeySymmetricDecoded decodedKey = m_upsc.exportSymmetricKey(keyCode, keyPIN);
		if( decodedKey == null ){
			fail("Key Export Fails");
		}else if( decodedKey.getBytes() == null ){
			fail("Key Export Fails");
		}

		KeySymmetricEncoded importedKey = m_upsc.importSymmetricKey(decodedKey, keyPIN);
		if( importedKey == null ){
			fail("Key Import Fails");
		}else if( importedKey.getBytes() == null ){
			fail("Key Import Fails");
		}

	}

}
