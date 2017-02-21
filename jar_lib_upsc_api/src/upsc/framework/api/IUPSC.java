/**
 *
 */
package upsc.framework.api;

/**
 * The public interface of the UpscApi.
 * @author Dick Meuleman 2015 / Minho, Yoo (paromix@curaysoft.com)
 *
 */
public interface IUPSC {
	/**
	 * Generates and wraps a symmetric key.
	 * @param the length of the key to be generated
	 * @param pin set this to protect the key(code) with a pin. Can be null, than askPin has to be false.
	 * @return The encrypted/wrapped symmetric key.
	 * @throws UPSCException
	 */
	public KeySymmetricEncoded createSymmetricKey(KeyLengthSymmetric length, byte [] pin) throws UPSCException;

	/**
	 * Generates and wraps an RSA key
	 * @param length the length of the key.
	 * @param pin set this to protect the key(code) with a pin. Can be null, than askPin has to be false.
	 * @return A keypair that consist of a plain public key and an RSAKeyCode, an encrypted/wrapped private key.
	 * @throws UPSCException
	 */
	public KeyRSAPair createAsymmetricKey(KeyLengthAsymmetric length, byte [] pin) throws UPSCException;

	/**
	 * Export a symmetric key.
	 * @param keyCode the keyCode from the key to be exported
	 * @param askPin ask the user to enter a pin. True if the keycode is pin protected.
	 * @return the key
	 * @throws UPSCException
	 */
	public KeySymmetricDecoded exportSymmetricKey(KeySymmetricEncoded keyCode, byte[] keyPIN) throws UPSCException;

	/**
	 * Export a symmetric key.
	 * @param keyCode the keyCode to be exported
	 * @param keyPIN PIN for the key.
	 * @return decoded key
	 * @throws UPSCException
	 */
	public KeyRSAPrivateDecoded exportAsymmetricKey(KeyRSAPrivateEncoded keyCode, byte[] keyPIN) throws UPSCException;

	/**
	 * Import an external symmetric key
	 * @param key the key to be imported
	 * @param pin the pin if the keycode has to be protected.
	 * @return the KeyCode of the imported key.
	 * @throws UPSCException
	 */
	public KeySymmetricEncoded importSymmetricKey(KeySymmetricDecoded key, byte [] pin) throws UPSCException;

	/**
	 * Import an external symmetric key
	 * @param private the key to be imported
	 * @param pin the pin if the private has to be protected.
	 * @return the KeyCode of the imported key.
	 * @throws UPSCException
	 */
	public KeyRSAPrivateEncoded importAsymmetricKey(KeyRSAPrivateDecoded privateKey, byte[] keyPIN) throws UPSCException;

	/**
	 * Encrypt some data with symmetric encryption (in case of SSF: AES-GCM)
	 * @param keyCode the KeyCode of the key to be used.
	 * @param keyPIN the PIN value for the keyCode.
	 * @param data the plain text to be encrypted.
	 * @return CipherText containing the IV and the encrypted data.
	 * @throws ExceUPSCExceptionption
	 */
	public CipherText encrypt(KeySymmetricEncoded keyCode, byte[] keyPIN, byte [] data) throws UPSCException;

	/**
	 * Encrypt some data with an RSA-AES hybrid
	 * @param publicKey the public key to protect the internally generated symmetric key with
	 * @param data the data to be encrypted
	 * @return A structure containing the iv, encrypted data and the RSA encrypted symmetric key.
	 * @throws UPSCException
	 */
	public CipherText encrypt(KeyRSAPublic publicKey, byte [] data) throws UPSCException;

	/**
	 * Decrypt a previously encrypted CipherText
	 * @param keyCode the keycode of the key to be used.
	 * @param keyPIN the PIN value for the keyCode.
	 * @param cipherText
	 * @return the decrypted data
	 * @throws UPSCException
	 */
	public byte [] decrypt(KeySymmetricEncoded keyCode, byte[] keyPIN, CipherText cipherText) throws UPSCException;

	/**
	 * Decrypt a previously encrypted AsymmetricCipherText
	 * @param keyCode the keyCode of the private key to be used
	 * @param keyPIN the PIN value for the keyCode.
	 * @param cipherText the asymmetric cipher text to be decrypted
	 * @return the decrypted data
	 * @throws UPSCException
	 */
	public byte [] decrypt(KeyRSAPrivateEncoded keyCode, byte[] keyPIN, CipherText cipherText) throws UPSCException;

	/**
	 * Encrypt a pin with a protected key
	 * @param keyCode the protected key
	 * @param PIN from the user and to be encrypted with symmetric key
	 * @return the encrypted pin
	 * @throws UPSCException
	 */
	public PinEncoded enrollPin(KeySymmetricEncoded keyCode, byte [] pin) throws UPSCException;

	/**
	 * Asks the user for a pin code and verifies it against a previously encrypted pin.
	 * @param keyCode the keycode with which the encrypted pin is protected
	 * @param encryptedPin the previously encrypted pin
	 * @param PIN to be verified with decrypted PIN
	 * @return true if the pin was verified, false if not
	 * @throws UPSCException
	 */
	public boolean verifyPin(KeySymmetricEncoded keyCode, PinEncoded encryptedPin, byte [] pin) throws UPSCException;

	/**
	 * Sign some data with a protected private key
	 * @param keyCode the keycode of the private key
	 * @param keyPIN the PIN value for the keyCode.
	 * @param data the data to be signed
	 * @return a signature of the data (SHA256withRSA)
	 * @throws UPSCException
	 */
	public byte [] sign(KeyRSAPrivateEncoded keyCode, byte[] keyPIN, byte [] data) throws UPSCException;

	/**
	 * Verify a signature of some data.
	 * @param key the public key to verify with
	 * @param data the data to verify
	 * @param signature
	 * @return true if the signature checks out, otherwise false.
	 * @throws UPSCException
	 */
	public boolean verify(KeyRSAPublic key, byte [] data,  byte [] signature) throws UPSCException;

	/**
	 *
	 * @return an identifier by which the type of UpscApi - which implementation - can be identified.
	 * @throws UPSCException
	 */
	public Information getInfo() throws UPSCException;

}
