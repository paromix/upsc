package upsc.api.test;

import android.util.Log;
import upsc.framework.api.Information;
import upsc.framework.api.KeyLengthSymmetric;
import upsc.framework.api.KeySymmetricDecoded;
import upsc.framework.api.KeySymmetricEncoded;
import upsc.framework.api.UPSCException;
import upsc.framework.api.UpscSIM;

public class TC_ExportSymmetricKey extends UPSCTestCase {
	public void testExportSymmetricKey192() throws Exception{
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
	}

	public void testExportSymmetricKey192WithWrongPIN() throws Exception{
		byte[] pin = {0x20, 0x20, 0x20, 0x20};
		KeySymmetricEncoded key = m_upsc.createSymmetricKey(
												KeyLengthSymmetric.GENERIC_192, 
												pin
												);
		if( key == null ){
			fail("Key Creation Fails");
		}else if( key.getBytes() == null ){
			fail("Key Creation Fails");
		}

		byte[] wrongPIN = {0x01, 0x02, 0x03, 0x04};
		try{
			KeySymmetricDecoded decodedKey = m_upsc.exportSymmetricKey(key, wrongPIN);
			fail("Not Reached");
		}catch(UPSCException e){
			// Pass
		}
	}

	public void testExportSymmetricKey256() throws Exception{
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
	}

	public void testExportSymmetricKey256WithWrongPIN() throws Exception{
		byte[] pin = {0x20, 0x20, 0x20, 0x20};
		KeySymmetricEncoded key = m_upsc.createSymmetricKey(
												KeyLengthSymmetric.GENERIC_256, 
												pin
												);
		if( key == null ){
			fail("Key Creation Fails");
		}else if( key.getBytes() == null ){
			fail("Key Creation Fails");
		}

		byte[] wrongPIN = {0x01, 0x02, 0x03, 0x04};
		try{
			KeySymmetricDecoded decodedKey = m_upsc.exportSymmetricKey(key, wrongPIN);
			fail("Not Reached");
		}catch(UPSCException e){
			// Pass
		}
	}

}
