package com.nfclab.upsc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class UPSCApplet extends Applet {

	public final static byte RSAKEYAPPLET_CLA = (byte) 0x80;
	public final static byte CREATE_SYMMETRIC_KEYS = (byte) 0x20;
	public final static byte CREATE_ASYMMETRIC_KEYS = (byte) 0x26;
	public final static byte REQUEST_KEY = (byte) 0x21;
	public final static byte KEY_RECEIVED = (byte) 0x22;
	public final static byte SYMMETRIC_ENCRYPTION = (byte) 0x23;
	public final static byte SYMMETRIC_DECRYPTION = (byte) 0x24;
	public final static byte ASYMMETRIC_ENCRYPTION = (byte) 0x27;
	public final static byte ASYMMETRIC_DECRYPTION = (byte) 0x28;
	public final static byte SIGN = (byte) 0x29;
	public final static byte KEY_EXPORT = (byte) 0x31;
	public final static byte KEY_IMPORT = (byte) 0x32;
	public final static byte ENROLL_PIN = (byte) 0x33;
	public final static byte VERIFY_PIN = (byte) 0x34;
	public final static byte VERIFY_SIGNATURE = (byte) 0x35;
	// RSA KEYS CANT BE GENERATED IN SIM CARD EXCEPTION MESSAGE
	public final static byte[] RSA_GENERATION_EXCEPTION = { (byte) 0xA0, (byte) 0xB0, (byte) 0xC0 };

	// SYMMETRIC KEYS CANT BE GENERATED IN SIM CARD EXCEPTION MESSAGE
	public final static byte[] SYMMETRIC_GENERATION_EXCEPTION = { (byte) 0xC0, (byte) 0xB0, (byte) 0xA0 };
	
	// RSA KEYS CANT BE GENERATED IN SIM CARD EXCEPTION MESSAGE
	public final static byte[] OBJECT_NOT_FOUNDED = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
	public final static byte[] SIGN_ERROR = { (byte) 0xA0, (byte) 0xB0, (byte) 0xC0 };

	RSAPrivateKey rsa_PrivateKey, rsa_PrivateKey_1024 ;
	RSAPublicKey rsa_PublicKey, rsa_PublicKey_1024;

	// VARIOUS VARIABLES USED THROUGHOUT ENCRYPTION AND DECRYPTION PROCESSES
	DESKey deskey;
	Cipher cipherCBC, cipherRSA;
	// private static short index = 1;

	private RandomData rd;
	private KeyPair rsa_KeyPair_1024;
	private Signature md5_sign;
	/*private byte[] private_key_mod, private_key_exp, public_key_mod,
			public_key_exp;*/
	private byte[] transactionID = new byte[8];
	private byte[] transactionID_symmetric = new byte[8];
	private byte[] transactionID_symmetric256 = new byte[8];
	private byte[] incomingTransactionID = new byte[8];
	private byte[] wrapp_key = new byte[32];
	private byte[] FourBytePin1 = new byte[4];
	private byte[] FourBytePin2 = new byte[4];
	byte[] AsymmetricPrivateKey = new byte[536]; //For 2048 bit RSA: 256 mod, 256 exponent, 4 pin, (4+8+8) 3DES. //For 1024 bit RSA: 128 mod, 128 exponent, 4 pin, (4+8+8) 3DES
	short AsymmetricPrivateKeyLength;
	byte[] AsymmetricPublicKey = new byte[536]; //For 2048 bit RSA: 
	short AsymmetricPublicKeyLength;
	private short temp1, temp2, publicKeyLength, dataLength, len, current_m, total_m, enc_result_length,wrappedKeyLength, privateKeyLength, compareResult, i, k, j, encryptLength, decryptLength;
	private byte byte1, byte2;
	private boolean bool_temp;
	
	//sendresultapdu metodunun degiskenleri
	private short total_length, compare, iterations, divide, src_offset, len_offset, des_offset;
	/*private byte[] masterKey = new byte[] { (byte) 0x4E, (byte) 0xF4,
			(byte) 0x31, (byte) 0x8E, (byte) 0x5B, (byte) 0xC7, (byte) 0x19,
			(byte) 0x0F, (byte) 0xEB, (byte) 0x41, (byte) 0x08, (byte) 0x59,
			(byte) 0x97, (byte) 0x94, (byte) 0x60, (byte) 0xD5, (byte) 0x0C,
			(byte) 0x55, (byte) 0xE2, (byte) 0x66, (byte) 0x83, (byte) 0x83,
			(byte) 0x83, (byte) 0x83};*/
	private byte[] masterKey = new byte[24];
	private byte[] wrappedSymmetric3DESKey = new byte[32];
	private byte[] symmetric3DESKey = new byte[] { (byte) 0x31, (byte) 0x8E,
			(byte) 0x5B, (byte) 0xC7, (byte) 0x4E, (byte) 0xF4, (byte) 0x31,
			(byte) 0x8E, (byte) 0x0C, (byte) 0x55, (byte) 0xE2, (byte) 0x66,
			(byte) 0x97, (byte) 0x94, (byte) 0x60, (byte) 0xD5, (byte) 0xBF,
			(byte) 0x43, (byte) 0xDC, (byte) 0xE0, (byte) 0x49, (byte) 0xB3,
			(byte) 0x3A, (byte) 0x34 };
	private byte[] symmetric256bitKey = new byte[32] ;
	private byte[] wrappedSymmetric256bitKey = new byte[40] ;
	private byte[] hybrid3DESKey = new byte[24] ;
	
	private byte[] temp256_1_ = new byte[(short) 256];
	private byte[] temp256_2_ = new byte[(short) 256];
	private byte[] temp256_3_ = new byte[(short) 256];
	private byte[] temp516_1_ = new byte[(short) 516];
	private byte[] totalParams = new byte[768];
	private byte[] temp_768_1_ = new byte[768];

	private UPSCApplet() {

		rd = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
				KeyBuilder.LENGTH_DES, false);
		cipherCBC = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
		cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		rd.generateData(masterKey, (short) 0, (short) 24);
		
		rsa_KeyPair_1024 = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
		rsa_PublicKey_1024 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
		rsa_PrivateKey_1024 = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
		md5_sign = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);

	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new UPSCApplet().register();
	}

	public void process(APDU apdu) throws ISOException {
		// TODO Auto-generated method stub

		byte[] buffer = apdu.getBuffer();
		if (selectingApplet()) {
			return;
		}
		if (((byte) (buffer[ISO7816.OFFSET_CLA] & (byte) 0xFC)) != RSAKEYAPPLET_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		
		 case CREATE_SYMMETRIC_KEYS:
			createSymmetricKey(apdu);
			break;
		case REQUEST_KEY:
			requestKey(apdu);
			break;
		case CREATE_ASYMMETRIC_KEYS:
			createAsymmetricKey(apdu);
			break; 
		case SYMMETRIC_ENCRYPTION:   
			symmetricEncryptionRequest(apdu);
			break;
		case SYMMETRIC_DECRYPTION:   
			symmetricDecryptionRequest(apdu);
			break;	// 
		case KEY_RECEIVED:   
			keyReceived(apdu);
			break;
		case ASYMMETRIC_ENCRYPTION:
			asymmetricEncryptionRequest(apdu);
			break;
		case ASYMMETRIC_DECRYPTION:
			asymmetricDecryptionRequest(apdu);
			break;
		case SIGN:   
			sign(apdu);
			break;
		case ENROLL_PIN:   
			enrollPin(apdu);
			break;
		case VERIFY_PIN:   
			verifyPin(apdu);
			break;
		case KEY_EXPORT:   
			keyExport(apdu);
			break;	
		case KEY_IMPORT:   
			keyImport(apdu);
			break;	
		case VERIFY_SIGNATURE:   
			verify(apdu);
			break;		
			
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

		}

	}
	
	
	private void asymmetricEncryptionRequest(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// THERE IS A PROBLEM WHEN SENDING LARGE NUMBERS INSIDE P1 AND P2. SO WE
		// DIVIDE THE NUMBER BY 4 .
		publicKeyLength = (short) (buffer[ISO7816.OFFSET_P1] * 4);
		dataLength = (short) (buffer[ISO7816.OFFSET_P2] * 4);
		len = apdu.setIncomingAndReceive();

		for (i = 0; i < (short) (len); i++) {
			temp256_1_[i] = buffer[(short) (i + 5)];
		}
		
		current_m = temp256_1_[0];
		total_m = temp256_1_[1];
		
		if(current_m <= total_m && current_m<= (short) 3){
            if((short) (len) >= 3)
                Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*(current_m-1)), (short) ((short) (len)-2));    
            }else if (current_m==(short) 3){
                if((short) (len) >= 3)
                    Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*2), (short) ((short) (len)-2));          
         
            }
			if (current_m == total_m) {
				//SETMODULUS VE EXPONENTTA PROBLEM VAR DAHA SONRA BAKILACAK
				// publicKeyLength
				rsa_PublicKey_1024.setModulus(totalParams, (short) 0,(short) (publicKeyLength - 4));
				rsa_PublicKey_1024.setExponent(totalParams, (short) (publicKeyLength - 4), (short) 3);

				//temp256_3_ holds plaintextdata
				Util.arrayCopy(totalParams, (short) publicKeyLength, temp256_3_, (short) 0, (short) dataLength);
				

				rd.generateData(hybrid3DESKey, (short) 0, (short) 24);
				deskey.setKey(hybrid3DESKey, (short) 0);
				cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
				cipherCBC.doFinal(temp256_3_, (short) 0, (short) dataLength,	temp256_1_, (short) 0);
				deskey.setKey(hybrid3DESKey, (short) 8);
				cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
				cipherCBC.doFinal(temp256_1_, (short) 0,(short) (dataLength + 8), temp256_2_, (short) 0);
				deskey.setKey(hybrid3DESKey, (short) 16);
				cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
				cipherCBC.doFinal(temp256_2_, (short) 0,(short) (dataLength + 16), temp256_1_, (short) 0);

				cipherRSA.init(rsa_PublicKey_1024, Cipher.MODE_ENCRYPT);
				// short x = cipherRSA.doFinal(hybrid3DESKey, (short) 0, (short) hybrid3DESKey.length, temp256_2_, (short) 0);
				// PADING YAPINCA BOYLE MI OLACAK ENCRYPTION KISMI
				padData((short) 128, hybrid3DESKey, (short) hybrid3DESKey.length); 
				enc_result_length = cipherRSA.doFinal(temp256_3_, (short) 0, (short) 128,temp256_2_, (short) 0);
				
				Util.arrayCopy(temp256_1_, (short) 0, totalParams, (short) 0, (short) (dataLength + 24));
				Util.arrayCopy(temp256_2_, (short) 0, totalParams,(short) (dataLength + 24), (short) (enc_result_length));

				//Util.arrayCopy(totalParams, (short) 0, buffer, (short) 0,(short) (dataLength + 24 + enc_result_length));
				
				sendResultApdu(apdu, totalParams, (short) (1), (short) (dataLength + 24 + enc_result_length));
				//sendResultApdu(apdu, totalParams, (short) (1), (short) (len-2));

		} else if (current_m > total_m) {
			sendResultApdu(apdu, totalParams,(short) (current_m - total_m + 1), (short) (dataLength + 24+ enc_result_length));
		}

	}
	
	private void asymmetricDecryptionRequest(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		wrappedKeyLength = (short) (buffer[ISO7816.OFFSET_P1] * 4);
		dataLength = (short) (buffer[ISO7816.OFFSET_P2] * 4);
		privateKeyLength = 0;
		len = apdu.setIncomingAndReceive();

		for (i = 0; i < (short) (len); i++) {
			temp256_1_[i] = buffer[(short) (i + 5)];
		}
		current_m = temp256_1_[0];
		total_m = temp256_1_[1];

		if(current_m <= total_m && current_m<= (short) 3){
            if((short) (len) >= 3)
                Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*(current_m-1)), (short) ((short) (len)-2));    
            }else if (current_m==(short) 3){
                if((short) (len) >= 3)
                    Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*2), (short) ((short) (len)-2));          
            }
		if (current_m == total_m) {
			if (wrappedKeyLength < (short) 512)
				privateKeyLength = (short) 128;
			else if (wrappedKeyLength < (short) 1024)
				privateKeyLength = (short) 256;
			///////////////
			Util.arrayCopy(totalParams, (short) (wrappedKeyLength),FourBytePin1, (short) (0), (short) (4));
            //unwrapped  = unwrap(totalParams, wrappedKeyLength);
            enc_result_length = unwrap_new(totalParams, wrappedKeyLength);
            
            Util.arrayCopy(temp_768_1_, (short) (privateKeyLength + privateKeyLength), FourBytePin2, (short) (0), (short) (4));
            if(Util.arrayCompare(FourBytePin1, (short) 0, FourBytePin2, (short) 0, (short) 4)==0){
			//try {
			//SETMOUDULUS VE SETEXPONENT SONRA TEST EDILECEK
            rsa_PrivateKey_1024.setModulus(temp_768_1_, (short) 0,(short) privateKeyLength);
            rsa_PrivateKey_1024.setExponent(temp_768_1_, (short) privateKeyLength, (short) (privateKeyLength));
			
        	//Decrypt encrypted 3DES key and save it to temp256_2_
            Util.arrayCopy(totalParams, (short) (wrappedKeyLength + 4 + dataLength - privateKeyLength), temp256_1_, (short) (0), (short) (privateKeyLength));
			cipherRSA.init(rsa_PrivateKey_1024, Cipher.MODE_DECRYPT);
			cipherRSA.doFinal(temp256_1_, (short) 0, (short) privateKeyLength, temp256_2_, (short) 0);
			Util.arrayCopy(temp256_2_, (short) (privateKeyLength-hybrid3DESKey.length), hybrid3DESKey,(short) (0), (short) 24);
			//hybrid3DESKey dogru cozuluyor.
			
			Util.arrayCopy(totalParams, (short) (wrappedKeyLength + 4),temp256_1_, (short) (0), (short) (dataLength - privateKeyLength));
			//temp256_1_ in icinde 40 byte veri var. Kontrol ettim dogru.

			// decrypt data with 3des
			deskey.setKey(hybrid3DESKey, (short) 16);
			cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
			cipherCBC.doFinal(temp256_1_, (short) 0, (short) (dataLength - privateKeyLength),temp256_2_, (short) 0);
			deskey.setKey(hybrid3DESKey, (short) 8);
			cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
			cipherCBC.doFinal(temp256_2_, (short) 0, (short) (dataLength - privateKeyLength - 8), temp256_1_, (short) 0);
			deskey.setKey(hybrid3DESKey, (short) 0);
			cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
			cipherCBC.doFinal(temp256_1_, (short) 0, (short) (dataLength - privateKeyLength - 16),temp256_2_, (short) 0);
			Util.arrayCopy(temp256_2_, (short) 0, totalParams, (short) (0), (short) (dataLength - privateKeyLength - 24));

		/*} catch (CryptoException ee) {
			if (ee.getReason() == CryptoException.INVALID_INIT)
				sendResultApdu(apdu, invalidInt, (short) 1,
						(short) (invalidInt.length));
			else if (ee.getReason() == CryptoException.UNINITIALIZED_KEY)
				sendResultApdu(apdu, unintilizedKey, (short) 1,
						(short) (unintilizedKey.length));
			else if (ee.getReason() == CryptoException.ILLEGAL_USE)
				sendResultApdu(apdu, illegalUse, (short) 1,
						(short) (illegalUse.length));
			}*/

			// tamam calisti
            }
            if(Util.arrayCompare(FourBytePin1, (short) 0, FourBytePin2, (short) 0, (short) 4)==0)
            	sendResultApdu(apdu, totalParams, (short) 1, (short) (dataLength - privateKeyLength - 24));
            else 
            	sendResultApdu(apdu, RSA_GENERATION_EXCEPTION, (short) 1, (short) (3));
			//sendResultApdu(apdu, totalParams, (short) (1), (short) (dataLength - privKeyLength - 24));
		} else if (current_m > total_m) {
			if(Util.arrayCompare(FourBytePin1, (short) 0, FourBytePin2, (short) 0, (short) 4)==0)
				 sendResultApdu(apdu, totalParams, (short) (current_m - total_m + 1), (short) (dataLength - privateKeyLength - 24));
			else 
            	sendResultApdu(apdu, RSA_GENERATION_EXCEPTION, (short) 1, (short) (3));
		}
	}
	
	private void padData(short totalLength, byte[] inputData, short dataLength) {

		for (i = 0; i < (short) (totalLength - dataLength); i++)
			temp256_3_[i] = (byte) 0x00;

		Util.arrayCopy(inputData, (short) 0, temp256_3_, (short) (totalLength - dataLength), dataLength);

	}
	
	

	private void symmetricEncryptionRequest(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		wrappedKeyLength = (short) buffer[ISO7816.OFFSET_P1];
		dataLength = apdu.setIncomingAndReceive();
		encryptLength = (short) (dataLength - wrappedKeyLength - 4);
		//byte[] data_to_encrypt = new byte[(short) (total_data_length - wrapped_key_length - 1)];

		for (i = 0; i < wrappedKeyLength; i++)
			wrapp_key[i] = buffer[(short) (i + 5)];

		for(k = 0; k < 4 ; k++)
			FourBytePin1[k] = buffer[(short)(5 + wrappedKeyLength + k)];
			
		for (j = 0; j < encryptLength; j++)
			temp256_2_[j] = buffer[(short) (j + 5 + 4 + wrappedKeyLength)];

		enc_result_length = unwrap_new(wrapp_key, (short) wrapp_key.length);
		//unwrapped key temp_768_1_ un icinde
		Util.arrayCopy(temp_768_1_, (short)24, FourBytePin2,(short) 0, (short) 4);
		
		compareResult = Util.arrayCompare(FourBytePin1, (short) 0, FourBytePin2, (short) 0, (short) 4);
		if(compareResult == 0){
			deskey.setKey(temp_768_1_, (short) 0);
			cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
			cipherCBC.doFinal(temp256_2_, (short) 0, (short) encryptLength,
					temp256_1_, (short) 0);
			deskey.setKey(temp_768_1_, (short) 8);
			cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
			cipherCBC.doFinal(temp256_1_, (short) 0,
					(short) (encryptLength + 8), temp256_2_, (short) 0);
			deskey.setKey(temp_768_1_, (short) 16);
			cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
			enc_result_length = cipherCBC.doFinal(temp256_2_, (short) 0, (short) (encryptLength + 16), temp256_1_, (short) 0);
			
			sendResultApdu(apdu, temp256_1_, (short) (1), (short) (enc_result_length));
			
			//Util.arrayCopy(temp256_1_, (short)0, buffer,(short) 0, (short) enc_result_length);
			//apdu.setOutgoingAndSend((short) 0, (short) enc_result_length);
		}else
		{
			sendResultApdu(apdu, SIGN_ERROR, (short) (1), (short) (SIGN_ERROR.length));
		}		
	}
	
private void symmetricDecryptionRequest(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		wrappedKeyLength = (short) buffer[ISO7816.OFFSET_P1];
		dataLength = apdu.setIncomingAndReceive();
		decryptLength = (short) (dataLength - wrappedKeyLength - 4);

		for (i = 0; i < wrappedKeyLength; i++)
			wrapp_key[i] = buffer[(short) (i + 5)];

		for(k = 0; k < 4 ; k++)
			FourBytePin1[k] = buffer[(short)(5 + wrappedKeyLength + k)];

		for (j = 0; j < decryptLength; j++)
			temp256_1_[j] = buffer[(short) (j + 5 + 4 + wrappedKeyLength)];

		
		enc_result_length = unwrap_new(wrapp_key, (short) wrapp_key.length);
		
		//unwrapped key temp_768_1_ un icinde
		Util.arrayCopy(temp_768_1_, (short) 24, FourBytePin2,(short) 0, (short) 4);
		
		compareResult = Util.arrayCompare(FourBytePin1, (short) 0, FourBytePin2, (short) 0, (short) 4);
		if(compareResult == 0){

		deskey.setKey(temp_768_1_, (short) 16);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		cipherCBC.doFinal(temp256_1_, (short) 0, (short) decryptLength,
				temp256_2_, (short) 0);
		deskey.setKey(temp_768_1_, (short) 8);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		cipherCBC.doFinal(temp256_2_, (short) 0, (short) (decryptLength - 8),
				temp256_1_, (short) 0);
		deskey.setKey(temp_768_1_, (short) 0);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		enc_result_length = cipherCBC.doFinal(temp256_1_, (short) 0, (short) (decryptLength - 16), temp256_2_, (short) 0);
		sendResultApdu(apdu, temp256_2_, (short) (1), (short) (enc_result_length));
		//Util.arrayCopy(temp256_2_, (short) 0, buffer,(short) 0, (short) enc_result_length);
		//apdu.setOutgoingAndSend((short) 0, (short) enc_result_length);
		}else
		{
			sendResultApdu(apdu, SIGN_ERROR, (short) (1), (short) (SIGN_ERROR.length));
		}
	}



	private void enrollPin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		wrappedKeyLength = (short) buffer[ISO7816.OFFSET_P1];
		dataLength = apdu.setIncomingAndReceive();
		
		//4 byte pin will be encrypted
		temp1 = 4;

		for (i = 0; i < wrappedKeyLength; i++)
			wrapp_key[i] = buffer[(short) (i + 5)];
		
		for (j = 0; j < temp1; j++)
			temp256_2_[j] = buffer[(short) (j + 5 + wrappedKeyLength)];

		//clear_key = unwrap(wrapp_key, (short) 0);
		enc_result_length = unwrap_new(wrapp_key, (short) wrapp_key.length);
		
		
		
		deskey.setKey(temp_768_1_, (short) 0);
		cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
		cipherCBC.doFinal(temp256_2_, (short) 0, (short) 4, temp256_1_, (short) 0);
		deskey.setKey(temp_768_1_, (short) 8);
		cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
		cipherCBC.doFinal(temp256_1_, (short) 0, (short) (8), temp256_2_, (short) 0);
		deskey.setKey(temp_768_1_, (short) 16);
		cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
		enc_result_length = cipherCBC.doFinal(temp256_2_, (short) 0, (short) (16), temp256_1_, (short) 0);
		
		sendResultApdu(apdu, temp256_1_, (short) (1), (short) (enc_result_length));
		
		//Util.arrayCopy(temp256_1_, (short)0, buffer,(short) 0, (short) enc_result_length);
		//apdu.setOutgoingAndSend((short) 0, (short) enc_result_length);

	}
	
	private void verifyPin(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		wrappedKeyLength = (short) buffer[ISO7816.OFFSET_P1];
		dataLength = apdu.setIncomingAndReceive();
		decryptLength = (short) (dataLength - wrappedKeyLength - 4);

		for (i = 0; i < wrappedKeyLength; i++)
			wrapp_key[i] = buffer[(short) (i + 5)];

		for(k = 0; k < 4 ; k++)
			FourBytePin1[k] = buffer[(short)(5 + wrappedKeyLength + decryptLength + k)];
			
		for (j = 0; j < decryptLength; j++)
			temp256_1_[j] = buffer[(short) (j + 5 + wrappedKeyLength)];

		//clear_key = unwrap(wrapp_key, (short) 0);
		enc_result_length = unwrap_new(wrapp_key, (short) wrapp_key.length);
		

		// decrypt data with 3des
		deskey.setKey(temp_768_1_, (short) 16);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		cipherCBC.doFinal(temp256_1_, (short) 0, (short) decryptLength,temp256_2_, (short) 0);
		deskey.setKey(temp_768_1_, (short) 8);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		cipherCBC.doFinal(temp256_2_, (short) 0, (short) (decryptLength - 8),temp256_1_, (short) 0);
		deskey.setKey(temp_768_1_, (short) 0);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		enc_result_length =cipherCBC.doFinal(temp256_1_, (short) 0, (short) (decryptLength - 16),temp256_2_, (short) 0);
		
		if(Util.arrayCompare(FourBytePin1, (short) 0, temp256_2_, (short) 0, (short) 4)==0)
			temp256_3_[0]=0x01;
		else
			temp256_3_[0]=0x00;
		
		sendResultApdu(apdu, temp256_3_, (short) (1), (short) (1));
		
		//apdu.setOutgoingAndSend((short) 0, (short) 1);
		
	}
	
	/*public byte[] unwrap(byte[] data,short len) {
	
		deskey.setKey(masterKey, (short) 0);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		
		short dataLen;
		if (len == (short) 0)
			dataLen = (short) data.length;
		else
			dataLen = len;

		if (dataLen == 32){
			cipherCBC.doFinal(data, (short) 0, (short) dataLen, res1, (short) 0);
			return res1;
		}
		else{
			cipherCBC.doFinal(data, (short) 0, (short) dataLen, res2, (short) 0);
			return res2;
		}

	}*/
	
	public short unwrap_new(byte[] data,short len) {
		
		deskey.setKey(masterKey, (short) 0);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		temp2 = cipherCBC.doFinal(data, (short) 0, (short) len, temp_768_1_, (short) 0);
		return temp2;
		
	}
	

	public short wrap_new(byte[] data, short length) {
		deskey.setKey(masterKey, (short) 0);
		cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
		temp2=cipherCBC.doFinal(data, (short) 0, (short) length, temp_768_1_, (short) 0);
		/*deskey.setKey(masterKey, (short) 8);
		cipherCBC.init(deskey, Cipher.MODE_DECRYPT);
		temp2=cipherCBC.doFinal(temp_768_1_, (short) 0, (short) temp2, temp_768_1_, (short) 0);
		deskey.setKey(masterKey, (short) 16);
		cipherCBC.init(deskey, Cipher.MODE_ENCRYPT);
		temp2=cipherCBC.doFinal(temp_768_1_, (short) 0, (short) temp2, temp_768_1_, (short) 0);*/
		return temp2;
	}
	
	
	
	public void createAsymmetricKey(APDU apdu) {

		
		byte[] buffer = apdu.getBuffer();
		byte1 = buffer[ISO7816.OFFSET_P1];
		len = apdu.setIncomingAndReceive();
		for(i = 0; i< len ; i++)
			FourBytePin1[i] = buffer[(short)(i+5)];
			
			if(byte1 == (byte) 0x01)
			{
				
				
				rsa_KeyPair_1024.genKeyPair();
				rsa_PrivateKey = (RSAPrivateKey) rsa_KeyPair_1024.getPrivate();
				rsa_PublicKey = (RSAPublicKey) rsa_KeyPair_1024.getPublic();
				
				generateTransactionID();
				
				rsa_PrivateKey.getModulus(AsymmetricPrivateKey, (short) 0);
				rsa_PrivateKey.getExponent(AsymmetricPrivateKey, (short) 128);
				Util.arrayCopy(FourBytePin1, (short) 0, AsymmetricPrivateKey,(short) (128 + 128),(short) FourBytePin1.length);

				AsymmetricPrivateKeyLength=wrap_new(AsymmetricPrivateKey,(short) (128 + 128+FourBytePin1.length));
				Util.arrayCopy(temp_768_1_, (short) 0, AsymmetricPrivateKey, (short) 0,(short) AsymmetricPrivateKeyLength);

				rsa_PublicKey.getModulus(AsymmetricPublicKey, (short) 0);
				rsa_PublicKey.getExponent(AsymmetricPublicKey, (short) 128);
				AsymmetricPublicKeyLength=128+4;

				sendResultApdu(apdu, transactionID, (short) (1), (short) transactionID.length);
			}
			
			/*if(rsaLength == (byte) 0x02)
			{
				
				
				rsa_PublicKey = (RSAPublicKey) KeyBuilder.buildKey(
						KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
				rsa_PrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(
						KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
				
				generateTransactionID();

				
				rd.generateData(pri_mod, (short) 0, (short) pri_mod.length);
				rsa_PrivateKey.setModulus (pri_mod, (short)0, (short)pri_mod.length);
			
				
				rd.generateData(pri_exponent, (short) 0, (short) pri_exponent.length);
				rsa_PrivateKey.setExponent (pri_exponent, (short)0, (short)pri_exponent.length);
				
				short pri_index;
				pri_index = rsa_PrivateKey.getModulus(rsa2048_pri, (short) 0);
				rsa_PrivateKey.getExponent(rsa2048_pri, (short) pri_index);
				Util.arrayCopy(FourBytePin1, (short) 0, rsa2048_pri, (short) 512,
						(short) FourBytePin1.length);

				encrypted = wrap(rsa2048_pri);
				
				short pub_index;
				pub_index = rsa_PublicKey.getModulus(rsa2048_pub, (short) 0);
				rsa_PublicKey.getExponent(rsa2048_pub, (short) pub_index);
				
				t = new Transaction(transID, encrypted, rsa2048_pub,(short)2);
				if(getAsymmetricObjectSize() < 3)
				{
					mal.add(t);
					t = null;
				}
				
				else
				{
					mal.remove(getAsymmetricObjectIndexToDelete());
					mal.add(t);
					t = null;
					
				}
				
				return transID;
				
				
			}*/
			
			else 
				sendResultApdu(apdu, RSA_GENERATION_EXCEPTION, (short) (1), (short) RSA_GENERATION_EXCEPTION.length);
	}
	
	public void requestKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		temp1 = (short) buffer[ISO7816.OFFSET_P1];
		temp2 = (short) buffer[ISO7816.OFFSET_P2];
		len = apdu.setIncomingAndReceive();

		for (i = 0; i < (short) len; i++) {
			incomingTransactionID[i] = buffer[(short) (i + 5)];
		}
		if (Util.arrayCompare(incomingTransactionID, (short) 0, transactionID, (short) 0, (short) len) == (short) 0) {
			Util.arrayCopy(AsymmetricPrivateKey,(short) 0,totalParams, (short)0, (short)AsymmetricPrivateKeyLength);
			Util.arrayCopy(AsymmetricPublicKey,(short) 0,totalParams, (short)AsymmetricPrivateKeyLength, (short) AsymmetricPublicKeyLength);
			sendResultApdu(apdu, totalParams, temp2, (short) (AsymmetricPrivateKeyLength+AsymmetricPublicKeyLength));
		}else if (Util.arrayCompare(incomingTransactionID, (short) 0, transactionID_symmetric, (short) 0, (short) len) == (short) 0) {
			sendResultApdu(apdu, wrappedSymmetric3DESKey, temp2, (short) wrappedSymmetric3DESKey.length);
		}else if (Util.arrayCompare(incomingTransactionID, (short) 0, transactionID_symmetric256, (short) 0, (short) len) == (short) 0) {
			sendResultApdu(apdu, wrappedSymmetric256bitKey, temp2, (short) wrappedSymmetric256bitKey.length);
		}else{
			sendResultApdu(apdu, OBJECT_NOT_FOUNDED, (short) (1), (short) (OBJECT_NOT_FOUNDED.length));
			
			//Util.arrayCopy(OBJECT_NOT_FOUNDED, (short) 0, buffer, (short) 0, (short) OBJECT_NOT_FOUNDED.length);
			//apdu.setOutgoingAndSend((short) 0, (short) OBJECT_NOT_FOUNDED.length);
		}
		
	}
	
	public void sendResultApdu(APDU apdu, byte[] data, short seq, short dataLen)
	{
		
		
		byte[] buffer = apdu.getBuffer();
		
		
		if (dataLen == 0) {
			total_length = (short) data.length;
			compare = (short) data.length;
		} else {
			total_length = (short) dataLen;
			compare = (short) dataLen;
		}

		//short block_size = (short) 253;
		divide = (short) (total_length / (short) 253);
		if (divide == 0)
			iterations = (short) (1);
		else
			iterations = (short) (divide + 1);

		if ((short) (seq * 253) > (short) (compare)) {
			buffer[0] = (byte) seq;
			buffer[1] = (byte) iterations;
			src_offset = (short) ((seq - 1) * 253);
			len_offset = (short) (compare - src_offset);
			Util.arrayCopy(data, src_offset, buffer, (short) 2, len_offset);
			apdu.setOutgoingAndSend((short) 0, (short) (len_offset + 2));
		} else {
			buffer[0] = (byte) seq;
			buffer[1] = (byte) iterations;
			src_offset = (short) ((seq - 1) * 253);
			len_offset = (short) ((seq * 253));
			Util.arrayCopy(data, src_offset, buffer, (short) 2, len_offset);
			des_offset = (short) (len_offset - src_offset);
			apdu.setOutgoingAndSend((short) 0, (short) (des_offset + 2));
		}
		
	}

	public void keyReceived(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		for (i = 0; i < (short) 8; i++) {
			incomingTransactionID[i] = buffer[(short) (i + 5)];
		}
		if (Util.arrayCompare(incomingTransactionID, (short) 0, transactionID, (short) 0, len) == (short) 0) {
			Util.arrayFillNonAtomic(transactionID, (short) 0, (short) transactionID.length, (byte) 0x00) ;
		}
	}

	public void generateTransactionID() {
		// TODO Auto-generated method stub
		rd.generateData(transactionID, (short) 0, (short) 8);
	}
	

    public void createSymmetricKey(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
		byte1 = buffer[ISO7816.OFFSET_P1];
		len = apdu.setIncomingAndReceive();
		for(i = 0; i< len ; i++)
			FourBytePin1[i] = buffer[(short)(i+5)];
		rd = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		
		
		
		
		/*if(keyLength==0x01)
		rd.generateData(symmetric3DESKey, (short) 0, (short) 24);
		 */
		
		if(byte1== (byte) 0x02){
			rd.generateData(transactionID_symmetric256, (short) 0, (short) 8);
			rd.generateData(symmetric256bitKey, (short) 0, (short) 32);
			Util.arrayCopy(symmetric256bitKey, (short) (0),temp256_1_, (short) (0), (short) symmetric256bitKey.length);
			Util.arrayCopy(FourBytePin1, (short) (0),temp256_1_, (short) symmetric256bitKey.length, (short) FourBytePin1.length);
			enc_result_length=wrap_new(temp256_1_, (short) 36);
			Util.arrayCopy(temp_768_1_, (short) 0, wrappedSymmetric256bitKey, (short) 0, (short) enc_result_length);
			sendResultApdu(apdu, transactionID_symmetric256, (short) (1), (short) transactionID_symmetric.length);
		}else if(byte1== (byte) 0x01){
			rd.generateData(transactionID_symmetric, (short) 0, (short) 8);
			Util.arrayCopy(symmetric3DESKey, (short) (0),temp256_1_, (short) (0), (short) symmetric3DESKey.length);
			Util.arrayCopy(FourBytePin1, (short) (0),temp256_1_, (short) symmetric3DESKey.length, (short) FourBytePin1.length);
			enc_result_length=wrap_new(temp256_1_, (short) 28);
			Util.arrayCopy(temp_768_1_, (short) 0, wrappedSymmetric3DESKey, (short) 0, (short) enc_result_length);
			sendResultApdu(apdu, transactionID_symmetric, (short) (1), (short) transactionID_symmetric.length);
			}
	}


private void keyExport(APDU apdu) {
	// TODO Auto-generated method stub
	
	byte[]  buffer = apdu.getBuffer();
	len = apdu.setIncomingAndReceive();
	dataLength = (short) (buffer[ISO7816.OFFSET_P2] * 4);
	for (i = 0; i < (short) (len); i++) {
		temp256_1_[i] = buffer[(short) (i + 5)];
	}
	current_m = temp256_1_[0];
	total_m = temp256_1_[1];

	if(current_m <= total_m && current_m<= (short) 3){
		if((short) (len) >= 3)
			Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*(current_m-1)), (short) ((short) (len)-2));    
	}else if (current_m==(short) 3){
		if((short) (len) >= 3){
			Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*2), (short) ((short) (len)-2));
		}
	}
	
	if (current_m == total_m) {
		Util.arrayCopy(totalParams, (short) dataLength, FourBytePin2, (short) (0), (short) (4)); 
		enc_result_length=unwrap_new(totalParams, (short) dataLength);
		//length enc_result_length de
		//temp = unwrap(totalParams, (short) ((total_m - 1) * 253+ len - 2));
				
		//Util.arrayCopy(temp, (short) 0, temp516_1_, (short) 0,(short) (temp.length));
		
		/*if (isSymetric == 0x01) {
			sendResultApdu(apdu, temp516_1_, (short) 1, (short) 24); // delete
																		// pin
		} else {
			sendResultApdu(apdu, temp516_1_, (short) 1,
					(short) ((total_m - 1) * 253 + len - 2 - 8));
		*/
		 Util.arrayCopy(temp_768_1_, (short) (enc_result_length-4), FourBytePin1, (short) (0), (short) (4)); 
		 if(Util.arrayCompare(FourBytePin1, (short) 0, FourBytePin2, (short) 0, (short) 4)==0)
			sendResultApdu(apdu, temp_768_1_, (short) (1), (short) (enc_result_length-4));
         else 
         	sendResultApdu(apdu, RSA_GENERATION_EXCEPTION, (short) 1, (short) (3));

	} else if (current_m > total_m) {
		sendResultApdu(apdu, temp_768_1_,(short) (current_m - total_m + 1), (short) (enc_result_length-4));
	}
/*
	} else if (current_m > total_m) {
		sendResultApdu(apdu, temp516_1_, (short) (current_m - total_m + 1),
				(short) ((total_m - 1) * 253 + len - 2 - 8));
	}*/

	
}

private void keyImport(APDU apdu) {
	// TODO Auto-generated method stub
	byte[]  buffer = apdu.getBuffer();
	//byte pinExists = buffer[ISO7816.OFFSET_P1];
	//byte isSymetric = buffer[ISO7816.OFFSET_P2];
	dataLength = (short) (buffer[ISO7816.OFFSET_P2] * 4);
	len = apdu.setIncomingAndReceive();
	for (i = 0; i < (short) (len); i++) {
		temp256_1_[i] = buffer[(short) (i + 5)];
	}
	current_m = temp256_1_[0];
	total_m = temp256_1_[1];

	if(current_m <= total_m && current_m<= (short) 3){
		if((short) (len) >= 3)
			Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*(current_m-1)), (short) ((short) (len)-2));    
	}else if (current_m==(short) 3){
		if((short) (len) >= 3)
			Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*2), (short) ((short) (len)-2));          
	}
	if (current_m == total_m) {
		enc_result_length=wrap_new(totalParams, (short) (dataLength+4));
		
		/*
		plainKey = new byte[(short) ((total_m - 1) * 250 + len - 2 + 4)];
		
		
		
		if (pinExists == 0x01)
			Util.arrayCopy(FourBytePin1, (short) 0, totalParams,
					(short) ((total_m - 1) * 250 + len - 2), (short) 4);
		Util.arrayCopy(totalParams, (short) 0, plainKey, (short) 0,
				(short) plainKey.length);
		temp520_1_ = wrap(plainKey);
		if (isSymetric == 0x01) {
			sendResultApdu(apdu, temp520_1_, (short) 1, (short) 32);
		} else {
			sendResultApdu(apdu, temp520_1_, (short) 1,
					(short) ((total_m - 1) * 253 + len - 2 + 8));// if
																	// pinExists
																	// 4
																	// ekle
																	// pinnotexist
																	// 8
																	// ekle
		*/
		sendResultApdu(apdu, temp_768_1_, (short) (1), (short) (enc_result_length));
	} else if (current_m > total_m) {
		sendResultApdu(apdu, temp_768_1_,(short) (current_m - total_m + 1), (short) (enc_result_length));
	}
	/*}
	} else if (current_m > total_m) {
		sendResultApdu(apdu, temp520_1_, (short) (current_m - total_m + 1),
				(short) ((total_m - 1) * 253 + len - 2 + 8));
	}*/
}

private void sign(APDU apdu) {
	// TODO Auto-generated method stub
	

	
	byte[] buffer = apdu.getBuffer();
	wrappedKeyLength = (short) (buffer[ISO7816.OFFSET_P1] * 4);
	dataLength = (short) (buffer[ISO7816.OFFSET_P2] * 4);
	privateKeyLength = 0;
	len = apdu.setIncomingAndReceive();

	enc_result_length = 0 ;

	for (i = 0; i < (short) (len); i++) {
		temp256_1_[i] = buffer[(short) (i + 5)];
	}
	current_m = temp256_1_[0];
	total_m = temp256_1_[1];

	if(current_m <= total_m && current_m<= (short) 3){
        if((short) (len) >= 3)
            Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*(current_m-1)), (short) ((short) (len)-2));    
        }else if (current_m==(short) 3){
            if((short) (len) >= 3)
                Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*2), (short) ((short) (len)-2));          
     }

        if(current_m == total_m){
        	if(wrappedKeyLength<512)
        		privateKeyLength=128;
        	else if(wrappedKeyLength<1024)
        		privateKeyLength=256;
        	
        	Util.arrayCopy(totalParams, (short) (wrappedKeyLength),FourBytePin1, (short) (0), (short) (4));
        	//unwrapped = unwrap(totalParams, wrappedKeyLength);
        	enc_result_length = unwrap_new(totalParams, wrappedKeyLength);
        	
            Util.arrayCopy(temp_768_1_, (short) (privateKeyLength + privateKeyLength), FourBytePin2, (short) (0), (short) (4));
            compareResult =Util.arrayCompare(FourBytePin1, (short) 0, FourBytePin2, (short) 0, (short) 4);
			if(compareResult == 0)
			{
				
				rsa_PrivateKey_1024.setModulus(temp_768_1_, (short) 0,(short) (privateKeyLength));
				rsa_PrivateKey_1024.setExponent(temp_768_1_, (short) (privateKeyLength), (short) privateKeyLength);
				
				
				md5_sign.init(rsa_PrivateKey_1024, Signature.MODE_SIGN); 
				
				//temp256_3_ holds plaintextdata
				Util.arrayCopy(totalParams, (short) (wrappedKeyLength + 4), temp256_2_, (short) 0, (short) dataLength);
				//padData((short) 128, temp256_2_, dataLength);
				
				/*cipherRSA.init(rsa_PrivateKey_1024, Cipher.MODE_ENCRYPT);
				padData((short) 128, temp256_2_, dataLength);
				enc_result_length = cipherRSA.doFinal(temp256_3_, (short) 0, (short) 128, temp516_1_, (short) 0);
				*/
				enc_result_length = md5_sign.sign(temp256_2_, (short) 0, (short) dataLength, temp516_1_, (byte) 0);
				Util.arrayCopy(temp516_1_, (short) 0, totalParams, (short) 0, (short) (enc_result_length));
				sendResultApdu(apdu, totalParams, (short) (1), (short) (enc_result_length));
			}
			else
			{
				sendResultApdu(apdu, SIGN_ERROR, (short) (1), (short) (SIGN_ERROR.length));
			}    		 
        }
    else if(current_m > total_m){
        sendResultApdu(apdu, totalParams, (short) (current_m - total_m+1), (short) (enc_result_length) );
    }
}

private void verify(APDU apdu) {
	// TODO Auto-generated method stub
	byte[]  buffer = apdu.getBuffer();
	publicKeyLength = (short) (buffer[ISO7816.OFFSET_P1] * 4);
	dataLength = (short) (buffer[ISO7816.OFFSET_P2] * 4);
	len = apdu.setIncomingAndReceive();
	for (i = 0; i < (short) (len); i++) {
		temp256_1_[i] = buffer[(short) (i + 5)];
	}
	current_m = temp256_1_[0];
	total_m = temp256_1_[1];

	if(current_m <= total_m && current_m<= (short) 3){
		if((short) (len) >= 3)
			Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*(current_m-1)), (short) ((short) (len)-2));    
	}else if (current_m==(short) 3){
		if((short) (len) >= 3)
			Util.arrayCopy(temp256_1_, (short) 2, totalParams, (short) (250*2), (short) ((short) (len)-2));          
	}
	if (current_m == total_m) {
		rsa_PublicKey_1024.setModulus(totalParams, (short) 0,(short) (publicKeyLength - 4));
		rsa_PublicKey_1024.setExponent(totalParams, (short) (publicKeyLength - 4), (short) 3);
		
		md5_sign.init(rsa_PublicKey_1024, Signature.MODE_VERIFY); 

		//datayi temp256_1_'e kopyala, sonra padding ile temp256_3_'de sakla
		Util.arrayCopy(totalParams, (short) (publicKeyLength), temp256_1_, (short) 0, (short) (dataLength));
		//padData((short) 128, temp256_1_, dataLength);

		//signature uzunlugu = publickeylength-4 
		//signature temp256_2_ de
		Util.arrayCopy(totalParams, (short) (publicKeyLength+dataLength), temp256_2_, (short) 0, (short) (publicKeyLength - 4));
		bool_temp = md5_sign.verify(temp256_1_, (short) 0, (short) dataLength, temp256_2_, (short) 0, (short) 128);
		if(bool_temp==true)
			temp256_3_[0]=0x01;
		else
			temp256_3_[0]=0x00;
		
		/*
		//datayi temp256_1_'e kopyala
		Util.arrayCopy(totalParams, (short) (publicKeyLength), temp256_1_, (short) 0, (short) (dataLength));
		
		//signature uzunlugu = publickeylength-4 
		Util.arrayCopy(totalParams, (short) (publicKeyLength+dataLength), temp256_3_, (short) 0, (short) (publicKeyLength - 4));
		
		cipherRSA.init(rsa_PublicKey_1024, Cipher.MODE_DECRYPT);
		enc_result_length = cipherRSA.doFinal(temp256_3_, (short) 0, (short) (publicKeyLength - 4),temp256_2_, (short) 0);

		//decrpt edilen signature'in 0x00'dan sonraki bytelarýný temp256_3_'e al
		Util.arrayCopy(temp256_2_, (short) (enc_result_length-dataLength), temp256_3_, (short) 0, (short) dataLength);
		
		bool_temp=false;
		if(Util.arrayCompare(temp256_1_, (short) 0, temp256_3_, (short) 0, (short) dataLength)==0){
			bool_temp=true;
			for (i = 0; i < (short) (enc_result_length - dataLength); i++)
				if(temp256_2_[i] != (byte) 0x00)
					bool_temp=false;	
		}
		if(bool_temp==true)
			temp256_3_[0]=0x01;
		else
			temp256_3_[0]=0x00;
		*/
		sendResultApdu(apdu, temp256_3_, (short) (1), (short) 1);
		
	} 
}

}

