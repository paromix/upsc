# upsc
UPSC framework and related sources


Mobile technology does not only provide voice communication but also provides a broad digital world where we can experience many vertical e-services. In this digital world, both the identity and the security of data transmission is very critical for the success of these e-services. However, by looking at the number of different mobile brands and open–source operating systems like Android, it might be difficult to provide a secure environment. Right at this stage, SIM cards might take an important role as a security service provider. They have been used for so many years to preserve the security keys(Ki) and algorithms (A3A8) for authenticating and encrypting the data. Recently, the new SIM cards can hold more than 512K Bytes of data, they have more CPU, and they are enhanced with cryptographic modules. More importantly, these SIM cards are produced in certified factories, where credit cards are also produced and they have a very big local distribution and support; the GSM operators. Thus, SIM cards provide us the ideal environment for security requirements of these new mobile e-services. Within this project, the international consortium will try to implement a software framework on both the mobile terminal and SIM card that expose the required security functions to popular e-services like Mobile commerce, Financial transactions, Data Encryption, Secure Cloud Storage and Mobile Identity. The consortium will also try to demonstrate the framework usage by integrating them into their products, showing how SIM card capabilities can be unleashed.

How to use UPSC Framework.

UPSC API is the simple framework to access SIM card capability.
First thing have to do is to initialize the UPSC framework like below.

<code>
IUPSC upsc = UpscSIM.getInstance(context); // 'context' is the instance of "android.content.Context" to access SIM.
</code>

To create symmetric key, use 'createSymmetricKey' method. Example is below.

<code>
KeySymmetricEncode key = upsc.createSymmetricKey(KeyLengthSymmetric.GENERIC_256, null);
</code>

You can encrypt the text with encoded key like below.

<code>
byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
try{
  CipherText encryptedData = m_upsc.encrypt(key, keyPin, data);
}catch(UPSCException e){
  // Something to do
}
</code>

Please read the API documents for more methods and details. 
