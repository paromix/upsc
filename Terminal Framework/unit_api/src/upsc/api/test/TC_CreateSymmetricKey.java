package upsc.api.test;

import android.util.Log;
import upsc.framework.api.Information;
import upsc.framework.api.KeyLengthSymmetric;
import upsc.framework.api.KeySymmetricEncoded;
import upsc.framework.api.UpscSIM;

public class TC_CreateSymmetricKey extends UPSCTestCase {
	public void testCreateSymmetricKey192Simple() throws Exception{
		KeySymmetricEncoded key = m_upsc.createSymmetricKey(
												KeyLengthSymmetric.GENERIC_192, 
												null
												);
		if( key == null ){
			fail("Key Creation Fails");
		}else if( key.getBytes() == null ){
			fail("Key Creation Fails");
		}
	}

	public void testCreateSymmetricKey192WithPIN() throws Exception{
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
	}

	public void testCreateSymmetricKey256Simple() throws Exception{
		KeySymmetricEncoded key = m_upsc.createSymmetricKey(
												KeyLengthSymmetric.GENERIC_256, 
												null
												);
		if( key == null ){
			fail("Key Creation Fails");
		}else if( key.getBytes() == null ){
			fail("Key Creation Fails");
		}
	}

	public void testCreateSymmetricKey256WithPIN() throws Exception{
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
	}

}
