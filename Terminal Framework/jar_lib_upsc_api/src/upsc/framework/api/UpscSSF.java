package upsc.framework.api;

import android.content.Context;
//import eu.intrinsicid.saturnus.securityframework.data.KeyCode;
import upsc.framework.ssf.api.*;

/**
 * The public class of {@link IUPSC}'s implements.
 * Only for SSF.
 */
public class UpscSSF implements IUPSC {

	private SsfUpscApi m_ssf_body = null;
	private static UpscSSF m_instance = null;
	
	private UpscSSF(Context ctx) throws UPSCException{
		try{
			m_ssf_body = SsfUpscApi.getInstance(ctx);
		}catch(Exception e){
			throw new UPSCException("SSF Get Instance occur Exception");
		}
	}
	/**
	 * Constructor of {@link UpscSSF}.	
	 * @param ctx Context of Application.
	 * @return Object of {@link UpscSSF}.
	 * @throws UPSCException
	 */	
	public synchronized static UpscSSF getInstance(Context ctx) throws UPSCException{
		if(m_instance == null){
			m_instance = new UpscSSF(ctx);
		}
		return m_instance;
	}
	
	@Override
	public KeySymmetricEncoded createSymmetricKey(KeyLengthSymmetric length, byte[] pin) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public KeyRSAPair createAsymmetricKey(KeyLengthAsymmetric length, byte[] pin) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public KeySymmetricDecoded exportSymmetricKey(KeySymmetricEncoded keyCode, byte[] keyPIN) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public KeySymmetricEncoded importSymmetricKey(KeySymmetricDecoded key, byte[] pin) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public CipherText encrypt(KeySymmetricEncoded keyCode, byte[] keyPIN, byte[] data) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public CipherText encrypt(KeyRSAPublic publicKey, byte[] data) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public byte[] decrypt(KeySymmetricEncoded keyCode, byte[] keyPIN, CipherText cipherText) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public byte[] decrypt(KeyRSAPrivateEncoded keyCode, byte[] keyPIN, CipherText cipherText) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public PinEncoded enrollPin(KeySymmetricEncoded keyCode, byte [] PIN) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public boolean verifyPin(KeySymmetricEncoded keyCode, PinEncoded encryptedPin, byte [] PIN) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public byte[] sign(KeyRSAPrivateEncoded keyCode, byte[] keyPIN, byte[] data) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public boolean verify(KeyRSAPublic key, byte[] data, byte[] signature) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}

	@Override
	public Information getInfo() throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}
	
	@Override
	public KeyRSAPrivateDecoded exportAsymmetricKey(KeyRSAPrivateEncoded keyCode, byte[] keyPIN) throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}
	@Override
	public KeyRSAPrivateEncoded importAsymmetricKey(KeyRSAPrivateDecoded privateKey, byte[] keyPIN)
			throws UPSCException {
		// TODO Auto-generated method stub
		throw new UPSCException("NOT IMPLEMENTED");
	}
}
