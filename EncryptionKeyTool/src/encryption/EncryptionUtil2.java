package encryption;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 針對加解密操作的工具類別，需置入相應的key<p>
 * 此版將Cipher改用每次加解密都重新創建，防止多執行續出錯。
 * 
 * @author EnixLin
 *
 */
public class EncryptionUtil2 {

	private String algorithm;
	private int keySize;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Cipher decryptionCipher, encryptionCipher;
	private final Decoder decoder;
	private final Encoder encoder;

	/**
	 * 預設值使用RSA，長度2048
	 */
	private EncryptionUtil2() {
		this.algorithm = "RSA";
		this.keySize = 2048;
		decoder = Base64.getMimeDecoder();
		encoder = Base64.getMimeEncoder();
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public int getKeySize() {
		return keySize;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public static class Builder {

		/** 預設數值 */
		EncryptionUtil2 keyReaderUtil = new EncryptionUtil2();

		public Builder setAlgorithm(String algorithm) {
			keyReaderUtil.algorithm = algorithm;
			return this;
		}

		public Builder setKeySize(int keySize) {
			keyReaderUtil.keySize = keySize;
			return this;
		}

		/** 僅能給定PKCS#8格式私鑰 */
		public Builder setPrivateKey(PrivateKey privateKey) {
			keyReaderUtil.privateKey = privateKey;
			return this;
		}

		/** 僅能給定X509格式公鑰 */
		public Builder setPublicKey(PublicKey publicKey) {
			keyReaderUtil.publicKey = publicKey;
			return this;
		}

		public EncryptionUtil2 build() {

			try {
				if (keyReaderUtil.privateKey != null) {
					Cipher decryptionCipher = Cipher.getInstance(keyReaderUtil.algorithm);
					decryptionCipher.init(Cipher.DECRYPT_MODE, keyReaderUtil.privateKey);
					keyReaderUtil.decryptionCipher = decryptionCipher;
				}
				if (keyReaderUtil.publicKey != null) {
					Cipher encryptionCipher = Cipher.getInstance(keyReaderUtil.algorithm);
					encryptionCipher.init(Cipher.ENCRYPT_MODE, keyReaderUtil.publicKey);
					keyReaderUtil.encryptionCipher = encryptionCipher;
				}
			} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new RuntimeException("Utility building failure. " + e.getMessage());
			}

			return keyReaderUtil;
		}
	}
	
	private Cipher getEncryptionCipher() {
		
		Cipher encryptionCipher;
		try {
			encryptionCipher = Cipher.getInstance(algorithm);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			throw new RuntimeException("Fail to get encryption cipher object.");
		}
		return encryptionCipher;
	}
	
	/**
	 * 將原始字串取得UTF8之byte陣列，以公鑰匙加密
	 * 
	 * @param originalString 欲加密之字串
	 * @return 加密後byte陣列
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] encryptInBytesByPublicKey(String originalString) {
		if (publicKey == null)
			throw new RuntimeException("There is no publicKey setted in this utility instance.");
		try {
			byte[] utf8Bytes = originalString.getBytes("UTF-8");
			return encryptionCipher.doFinal(utf8Bytes);
		} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
			throw new RuntimeException("Encryption failure. " + e.getMessage());
		}
	}

	/**
	 * 將原byte陣列以公鑰匙加密為新陣列
	 * 
	 * @param originalBytes 欲加密之byte陣列
	 * @return 加密後byte陣列
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] encryptInBytesByPublicKey(byte[] originalBytes) {
		if (publicKey == null)
			throw new RuntimeException("There is no publicKey setted in this utility instance.");
		try {
			return encryptionCipher.doFinal(originalBytes);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException("Encryption failure. " + e.getMessage());
		}
	}

	/**
	 * 將原始字串取得UTF8之byte陣列，以公鑰匙加密後，再使用Base64轉成字串表示
	 * 
	 * @param originalString 欲加密之字串
	 * @return 加密後的字串
	 */
	public String encryptInStringByPublicKey(String originalString) {
		if (publicKey == null)
			throw new RuntimeException("There is no publicKey setted in this utility instance.");
		try {
			byte[] utf8Bytes = originalString.getBytes("UTF-8");
			return encoder.encodeToString(encryptionCipher.doFinal(utf8Bytes));
		} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
			throw new RuntimeException("Encryption failure. " + e.getMessage());
		}
	}

	/**
	 * 將原始byte陣列以公鑰匙加密為新byte陣列後使用Base64轉成字串表示
	 * 
	 * @param originalBytes 欲加密之byte陣列
	 * @return 加密後的字串
	 */
	public String encryptInStringByPublicKey(byte[] originalBytes) {
		if (publicKey == null)
			throw new RuntimeException("There is no publicKey setted in this utility instance.");
		try {
			return encoder.encodeToString(encryptionCipher.doFinal(originalBytes));
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException("Encryption failure. " + e.getMessage());
		}
	}

	/**
	 * 將加密過後的陣列解密
	 * 
	 * @param encryptedBytes
	 * @return 解密後的byte陣列
	 */
	public byte[] decryptByPrivateKey(byte[] encryptedBytes) {
		if (privateKey == null)
			throw new RuntimeException("There is no privateKey setted in this utility instance.");
		try {
			return decryptionCipher.doFinal(encryptedBytes);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException("Decryption failure. " + e.getMessage());
		}
	}

	/**
	 * 將加密過後的內容(Base64)轉為byte陣列
	 * 
	 * @param encryptedBase64String base64的加密字串
	 * @return 解密後的byte陣列
	 */
	public byte[] decryptByPrivateKey(String encryptedBase64String) {
		if (privateKey == null)
			throw new RuntimeException("There is no privateKey setted in this utility instance.");
		try {
			return decryptionCipher.doFinal(decoder.decode(encryptedBase64String));
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException("Decryption failure. " + e.getMessage());
		}
	}

	/**
	 * 將加密過後的陣列解密為新字串(UTF-8)
	 * 
	 * @param encryptedBytes
	 * @return 解密後的字串
	 */
	public String decryptInStringByPrivateKey(byte[] encryptedBytes) {
		if (privateKey == null)
			throw new RuntimeException("There is no privateKey setted in this utility instance.");
		try {
			return new String(decryptionCipher.doFinal(encryptedBytes), "UTF-8");
		} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
			throw new RuntimeException("Decryption failure. " + e.getMessage());
		}
	}

	/**
	 * 將加密過後的內容(Base64)轉為原始字串(UTF-8)
	 * 
	 * @param encryptedBase64String base64的加密字串
	 * @return 解密後的字串
	 */
	public String decryptInStringByPrivateKey(String encryptedBase64String) {
		if (privateKey == null)
			throw new RuntimeException("There is no privateKey setted in this utility instance.");
		try {
			return new String(decryptionCipher.doFinal(decoder.decode(encryptedBase64String)), "UTF-8");
		} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
			throw new RuntimeException("Decryption failure. " + e.getMessage());
		}
	}
}
