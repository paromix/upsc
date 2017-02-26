package upsc.api.test;

import android.test.AndroidTestCase;
import upsc.framework.api.KeyLengthAsymmetric;
import upsc.framework.api.KeyRSAPair;
import upsc.framework.api.UpscSIM;
import upsc.framework.api.UpscSIMEmulation;

public class RSASample extends AndroidTestCase {
	public void testSignSimple() throws Exception{
		
		// To USE UPSC with SIM Emulation Mode
		//UpscSIM upsc = UpscSIMEmulation.getInstance(getContext());
		// To USE UPSC with SIM card
		UpscSIM upsc = UpscSIM.getInstance(getContext());
		
		byte[] keyPIN = {0x01, 0x02, 0x03, 0x04};

		KeyRSAPair keyPair = upsc.createAsymmetricKey(
				KeyLengthAsymmetric.RSA_1024, 
				keyPIN
				);
		byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		byte[] signedData = upsc.sign(keyPair.getPrivateKey(), keyPIN, data);
		
		if( signedData == null ){
			fail("Sign Fails");
		}
	}
}
