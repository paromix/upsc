package upsc.framework.api;

import com.curaysoft.upsc.comm.CommManager;

import android.content.Context;

/**
 * The public class of {@link IUPSC}'s implements.
 * Only for SIM Emulation.
 */
public class UpscSIMEmulation extends UpscSIM{

	//private static UpscSIM m_instance = null;

	private UpscSIMEmulation(Context ctx) throws UPSCException{
		m_commManager = new CommManager();
		m_commManager.initialize(ctx, CommManager.COMMUNICATE_WITH_SIM_EMUL);
		m_connector = m_commManager.getConnector();
	}

	/**
	 * Constructor of {@link UpscSIMEmulation}.
	 * @param ctx Context of Application.
	 * @return Object of {@link UpscSIMEmulation}.
	 * @throws UPSCException
	 */
	public synchronized static UpscSIM getInstance(Context ctx) throws UPSCException{
		return new UpscSIMEmulation(ctx);
		/*
		if(m_instance == null){
			m_instance = new UpscSIMEmulation(ctx);
		}
		return m_instance;
		*/
	}

	@Override
	public KeySymmetricEncoded createSymmetricKey(KeyLengthSymmetric length, byte[] pin) throws UPSCException {
		return super.createSymmetricKey(length, pin);
	}

	@Override
	public KeyRSAPair createAsymmetricKey(KeyLengthAsymmetric length, byte[] pin) throws UPSCException {
		return super.createAsymmetricKey(length, pin);
	}

	@Override
	public KeySymmetricDecoded exportSymmetricKey(KeySymmetricEncoded keyCode, byte[] keyPIN) throws UPSCException {
		return super.exportSymmetricKey(keyCode, keyPIN);
	}

	@Override
	public KeySymmetricEncoded importSymmetricKey(KeySymmetricDecoded key, byte[] pin) throws UPSCException {
		return super.importSymmetricKey(key, pin);
	}

	@Override
	public CipherText encrypt(KeySymmetricEncoded keyCode, byte[] keyPIN, byte[] data) throws UPSCException {
		return super.encrypt(keyCode, keyPIN, data);
	}

	@Override
	public CipherText encrypt(KeyRSAPublic publicKey, byte[] data) throws UPSCException {
		return super.encrypt(publicKey, data);
	}

	@Override
	public byte[] decrypt(KeySymmetricEncoded keyCode, byte[] keyPIN, CipherText cipherText) throws UPSCException {
		return super.decrypt(keyCode, keyPIN, cipherText);
	}

	@Override
	public byte[] decrypt(KeyRSAPrivateEncoded keyCode, byte[] keyPIN, CipherText cipherText) throws UPSCException {
		return super.decrypt(keyCode, keyPIN, cipherText);
	}

	@Override
	public PinEncoded enrollPin(KeySymmetricEncoded keyCode, byte [] pin) throws UPSCException {
		return super.enrollPin(keyCode, pin);
	}

	@Override
	public boolean verifyPin(KeySymmetricEncoded keyCode, PinEncoded encryptedPin, byte [] pin) throws UPSCException {
		return super.verifyPin(keyCode, encryptedPin, pin);
	}

	@Override
	public byte[] sign(KeyRSAPrivateEncoded keyCode, byte[] keyPIN, byte[] data) throws UPSCException {
		return super.sign(keyCode, keyPIN, data);
	}

	@Override
	public boolean verify(KeyRSAPublic key, byte[] data, byte[] signature) throws UPSCException {
		return super.verify(key, data, signature);
	}

	@Override
	public KeyRSAPrivateEncoded importAsymmetricKey(KeyRSAPrivateDecoded privateKey, byte[] pin) throws UPSCException {
		return super.importAsymmetricKey(privateKey, pin);
	}

	@Override
	public Information getInfo() throws UPSCException {
		return super.getInfo();
	}

}
