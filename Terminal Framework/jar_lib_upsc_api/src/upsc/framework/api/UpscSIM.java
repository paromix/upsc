package upsc.framework.api;

import android.content.Context;
import android.util.Log;

import com.curaysoft.upsc.comm.CommException;
import com.curaysoft.upsc.comm.CommManager;
import com.curaysoft.upsc.comm.IConnector;
import com.curaysoft.upsc.comm.KeyPairParser;

/**
 * The public class of {@link IUPSC}'s implements.
 * Only for SIM card.
 */
public class UpscSIM implements IUPSC {

	private static final String LOG_TAG = "UpscSIM";
	CommManager m_commManager = null;
	IConnector m_connector = null;
	//private static UpscSIM m_instance = null;
	private Context m_AppContext;

	UpscSIM(){
	}

	private UpscSIM(Context ctx) throws UPSCException{
		m_commManager = new CommManager();
		m_commManager.initialize(ctx, CommManager.COMMUNICATE_WITH_SIM);
		m_connector = m_commManager.getConnector();
		m_AppContext = ctx;
	}

	/**
	 * Constructor of {@link UpscSIM}.
	 * @param ctx Context of Application.
	 * @return Object of {@link UpscSIM}.
	 * @throws UPSCException
	 */
	public synchronized static UpscSIM getInstance(Context ctx) throws UPSCException{
		return new UpscSIM(ctx);
	}

	private void connect() throws UPSCException {
		if(!m_connector.connect()){
			throw new UPSCException("SIM Connection Fail");
		}
	}

	private void disconnect(){
		m_connector.disconnect();
	}

	@Override
	public KeySymmetricEncoded createSymmetricKey(KeyLengthSymmetric length, byte[] pin) throws UPSCException {

		byte keyLen;
		switch(length){
			case AES_192:
			case GENERIC_192:
				keyLen = IConnector.SYMMETRIC_KEY_LEN_192;
				break;

			case AES_256:
			case GENERIC_256:
				keyLen = IConnector.SYMMETRIC_KEY_LEN_256;
				break;

			default:
				throw new UPSCException("Key Length Not Supported");
		}

		connect();

		byte[] transactionId = m_connector.createSymmetricKey(keyLen, pin);
		if(transactionId == null){
			disconnect();
			throw new UPSCException("Key Generation Fail from SIM");
		}

		byte[] rvKey = m_connector.requestKeySymmetric(transactionId);
		if(rvKey == null){
			disconnect();
			throw new UPSCException("Key Generation Fail from SIM");
		}

		m_connector.keyReceived(transactionId);

		disconnect();

		KeySymmetricEncoded newKey = new KeySymmetricEncoded(rvKey, length);


		return newKey;
	}

	@Override
	public KeyRSAPair createAsymmetricKey(KeyLengthAsymmetric length, byte[] pin) throws UPSCException {

		byte keyLen;
		switch(length){
			case RSA_1024:
				keyLen = IConnector.ASYMMETRIC_KEY_LEN_1024;
				break;

			case RSA_2048:
				throw new UPSCException("Key Length Not Supported");

			default:
				throw new UPSCException("Key Length Not Supported");
		}

		connect();

		byte[] transactionId = m_connector.createAsymmetricKey(keyLen, pin);
		if(transactionId == null){
			disconnect();
			throw new UPSCException("Key Generation Fail from SIM");
		}

		byte[] rvKey = m_connector.requestKeyAsymmetric(transactionId);
		if(rvKey == null){
			disconnect();
			throw new UPSCException("Key Generation Fail from SIM");
		}

		m_connector.keyReceived(transactionId);

		disconnect();

		KeyPairParser parser = new KeyPairParser(m_connector);
		try{
			parser.doParse(keyLen, rvKey);
		}catch(CommException e){
			throw new UPSCException("Key Format Invalid");
		}

		KeyRSAPair newKey = new KeyRSAPair(parser.getPrivate(), parser.getPublic());

		return newKey;
	}

	@Override
	public KeySymmetricDecoded exportSymmetricKey(KeySymmetricEncoded keyCode, byte[] keyPIN) throws UPSCException {
		if( keyCode == null ){
			throw new UPSCException("Invalid Parameter");
		}

		switch(keyCode.getKeyLength()){
			case AES_192:
			case GENERIC_192:
			case AES_256:
			case GENERIC_256:
				break;
	
			default:
				throw new UPSCException("Key Length Not Supported");
		}

		// #
		//
		
		byte[] wrappedKey = keyCode.getBytes();

		connect();
		byte[] keyValue = m_connector.keyExportSymmetric(wrappedKey, keyPIN);
		disconnect();

		if( keyValue == null ){
			throw new UPSCException("Key Export Fail from SIM");
		}
		
		KeySymmetricDecoded decodedKey = new KeySymmetricDecoded(keyValue, keyCode.getKeyLength());

		return decodedKey;
	}
	
	@Override
	public KeyRSAPrivateDecoded exportAsymmetricKey(KeyRSAPrivateEncoded keyCode, byte[] keyPIN) throws UPSCException {
		if( keyCode == null ){
			throw new UPSCException("Invalid Parameter");
		}

		byte[] wrappedKey = keyCode.getBytes();

		connect();
		byte[] keyValue = m_connector.keyExportAsymmetric(wrappedKey, keyPIN);
		disconnect();

		if( keyValue == null ){
			throw new UPSCException("Key Export Fail from SIM");
		}
		
		KeyRSAPrivateDecoded decodedKey = new KeyRSAPrivateDecoded(keyValue);

		return decodedKey;
	}

	@Override
	public KeySymmetricEncoded importSymmetricKey(KeySymmetricDecoded keyValue, byte[] keyPIN) throws UPSCException {
		if( keyValue == null ){
			throw new UPSCException("Invalid Parameter");
		}

		switch(keyValue.getKeyLength()){
			case AES_192:
			case GENERIC_192:
			case AES_256:
			case GENERIC_256:
				break;
			default:
				throw new UPSCException("Key Length Not Supported");
		}
		
		// #
		//
		
		connect();
		byte[] wrappedKey = m_connector.keyImportSymmetric(keyValue.getBytes(), keyPIN);
		disconnect();
		
		if( wrappedKey == null ){
			throw new UPSCException("Key Import Fail from SIM");
		}

		KeySymmetricEncoded keyCode = new KeySymmetricEncoded(wrappedKey, keyValue.getKeyLength());

		return keyCode;
	}

	@Override
	public KeyRSAPrivateEncoded importAsymmetricKey(KeyRSAPrivateDecoded privateKey, byte[] keyPIN) throws UPSCException {
		if( privateKey == null ){
			throw new UPSCException("Invalid Parameter");
		}

		byte[] plainKey = privateKey.getBytes();

		connect();
		byte[] wrappedKey = m_connector.keyImportAsymmetric(plainKey, keyPIN);
		disconnect();

		if( wrappedKey == null ){
			throw new UPSCException("Key Export Fail from SIM");
		}
		
		KeyRSAPrivateEncoded encodedKey = new KeyRSAPrivateEncoded(wrappedKey);

		return encodedKey;
	}

	@Override
	public CipherText encrypt(KeySymmetricEncoded keyCode, byte[] keyPIN, byte[] data) throws UPSCException {

		if(keyCode == null || data == null){
			throw new UPSCException("Invalid Parameter");
		}
		
		// #
		//
		
		byte[] wrappedKey = keyCode.getBytes();
		KeyLengthSymmetric keyLen = keyCode.getKeyLength();
		switch(keyLen){
			case AES_192:
			case GENERIC_192:
				break;
	
			case AES_256:
			case GENERIC_256:
				throw new UPSCException("Key Length Not Supported");
	
			default:
				throw new UPSCException("Key Length Not Supported");
		}
		

		connect();
		byte[] encryptedData = m_connector.symmetricEncryptionRequest(wrappedKey, keyPIN, data);
		disconnect();

		if( encryptedData == null ){
			throw new UPSCException("Encryption Fail from SIM");
		}

		CipherText cipherText = new CipherText(encryptedData);


		return cipherText;
	}

	@Override
	public CipherText encrypt(KeyRSAPublic publicKey, byte[] data) throws UPSCException {

		if(publicKey == null || data == null){
			throw new UPSCException("Invalid Parameter");
		}
		
		// #
		//

		connect();
		byte[] encryptedData = m_connector.asymmetricEncryptRequest(
														publicKey.getBytes(), 
														data);
		disconnect();

		if( encryptedData == null ){
			throw new UPSCException("Encryption Fail from SIM");
		}

		CipherText cipherText = new CipherText(encryptedData);
		return cipherText;
	}

	@Override
	public byte[] decrypt(KeySymmetricEncoded keyCode, byte[] keyPIN, CipherText cipherText) throws UPSCException {

		if(keyCode == null || cipherText == null){
			throw new UPSCException("Invalid Parameter");
		}
		
		// #
		//

		byte[] wrappedKey = keyCode.getBytes();
		KeyLengthSymmetric keyLen = keyCode.getKeyLength();
		switch(keyLen){
			case AES_192:
			case GENERIC_192:
				break;
	
			case AES_256:
			case GENERIC_256:
				throw new UPSCException("Key Length Not Supported");
	
			default:
				throw new UPSCException("Key Length Not Supported");
		}

		byte[] encryptedData = cipherText.getBytes();
		connect();
		byte[] decryptedData = m_connector.symmetricDecryptionRequest(wrappedKey, keyPIN, encryptedData);
		disconnect();

		if( decryptedData == null ){
			throw new UPSCException("Decryption Fail from SIM");
		}

		return decryptedData;
	}

	@Override
	public byte[] decrypt(KeyRSAPrivateEncoded keyCode, byte[] keyPIN, CipherText cipherText) throws UPSCException {

		if(keyCode == null || cipherText == null){
			throw new UPSCException("Invalid Parameter");
		}
		
		// #
		//

		connect();
		byte[] decryptedData = m_connector.asymmetricDecryptRequest(
														keyCode.getBytes(),
														keyPIN,
														cipherText.getBytes());
		disconnect();

		if( decryptedData == null ){
			throw new UPSCException("Decryption Fail from SIM");
		}

		return decryptedData;
	}

	@Override
	public PinEncoded enrollPin(KeySymmetricEncoded keyCode, byte[] pin) throws UPSCException {

		if( keyCode == null || pin == null ){
			throw new UPSCException("Invalid Parameter");
		}

		byte[] wrappedKey = keyCode.getBytes();

		connect();

		byte[] encryptedkey = m_connector.enrollPIN(wrappedKey, pin);

		disconnect();

		if( encryptedkey  == null ){
			throw new UPSCException("Enroll PIN Fail from SIM");
		}

		PinEncoded newPIN = new PinEncoded(encryptedkey);

		return newPIN;
	}

	@Override
	public boolean verifyPin(KeySymmetricEncoded keyCode, PinEncoded encryptedPin, byte[] pin) throws UPSCException {

		if( keyCode == null || encryptedPin == null || pin == null ){
			throw new UPSCException("Invalid Parameter");
		}

		byte[] wrappedKey = keyCode.getBytes();
		byte[] encPIN = encryptedPin.getBytes();

		connect();

		byte resp = m_connector.verifyPIN(wrappedKey, encPIN, pin);

		disconnect();

		if( resp == IConnector.VERIFY_PIN_FAIL ){
			return false;
		}else if( resp == IConnector.VERIFY_PIN_SUCCESS ){
			return true;
		}else{
			throw new UPSCException("Invalid Response");
		}
	}

	@Override
	public byte[] sign(KeyRSAPrivateEncoded keyCode, byte[] keyPIN, byte[] data) throws UPSCException {

		Log.i(LOG_TAG, "ENTER sign()");

		if( keyCode == null || data == null ){
			throw new UPSCException("Invalid Parameter");
		}

		byte[] wrappedKey = keyCode.getBytes();

		connect();
		byte[] signedData = m_connector.asymmetricSignRequest(wrappedKey, keyPIN, data);
		disconnect();

		if( signedData == null ){
			throw new UPSCException("Decryption Fail from SIM");
		}

		Log.i(LOG_TAG, "Leave sign()");

		return signedData;
	}

	@Override
	public boolean verify(KeyRSAPublic key, byte[] data, byte[] signature) throws UPSCException {
		if( key == null || data == null || signature == null ){
			throw new UPSCException("Invalid Parameter");
		}

		byte[] keyValue = key.getBytes();
		
		connect();
		byte resp = m_connector.asymmetricVerifySignatureRequest(keyValue, data, signature);
		disconnect();

		if( resp == IConnector.VERIFY_SIGN_FAIL ){
			return false;
		}else if( resp == IConnector.VERIFY_SIGN_SUCCESS ){
			return true;
		}else{
			throw new UPSCException("Invalid Response");
		}
	}

	@Override
	public Information getInfo() throws UPSCException {
		Information info = new Information();
		String commModuleInfo = m_commManager.getVersion();
		info.SetCommModuleInfo(commModuleInfo);
		return info;
	}
}
