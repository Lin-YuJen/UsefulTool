package encryption;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.List;

/**
 * 針對金鑰操作的工具類別
 * 
 * @author EnixLin
 *
 */
public class RSAKeyUtil {

	private KeyPairGenerator keyPairGenerator;
	private String algorithm;
	private int keySize;
	private KeyFactory factory;
	private Decoder decoder;
	private Encoder encoder;

	/**
	 * 預設值使用RSA，長度2048
	 */
	private RSAKeyUtil() {
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

	public static class Builder {

		/** 預設數值 */
		private RSAKeyUtil keyUtil = new RSAKeyUtil();

//		public Builder setAlgorithm(String algorithm) {
//
//			keyUtil.algorithm = algorithm;
//			return this;
//		}

		public Builder setKeySize(int keySize) {

			keyUtil.keySize = keySize;
			return this;
		}

		public RSAKeyUtil build() {

			KeyPairGenerator keyPairGenerator;
			try {
				keyPairGenerator = KeyPairGenerator.getInstance(keyUtil.getAlgorithm());
				keyPairGenerator.initialize(keyUtil.getKeySize(), new SecureRandom());
				keyUtil.keyPairGenerator = keyPairGenerator;
				keyUtil.factory = KeyFactory.getInstance(keyUtil.algorithm);
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("No Such Algorithm. Please check again.");
			}
			return keyUtil;
		}
	}

	/**
	 * 取得產生的KeyPair<br>
	 * 公鑰以X.509規格產出，私鑰以PKCS#8規格產出
	 * 
	 * @return
	 */
	public KeyPair generateKeyPair() {
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * 將給定的key存起來，PEM編碼儲存於指定位置
	 * 
	 * @param keyPair
	 * @param publicKeyPath  公鑰存放位置，含檔名
	 * @param privateKeyPath 私鑰存放位置，含檔名
	 */
	public void saveKeyPairInPEM(KeyPair keyPair, Path publicKeyPath, Path privateKeyPath) {

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		StringBuilder publicPemFile = new StringBuilder("-----BEGIN PUBLIC KEY-----" + System.lineSeparator());
		String publicPemBody = new String(encoder.encodeToString(publicKey.getEncoded()));
		publicPemFile.append(publicPemBody + System.lineSeparator());
		publicPemFile.append("-----END PUBLIC KEY-----");

		StringBuilder privatePemFile = new StringBuilder("-----BEGIN PRIVATE KEY-----" + System.lineSeparator());
		String privatePemBody = new String(encoder.encodeToString(privateKey.getEncoded()));
		privatePemFile.append(privatePemBody + System.lineSeparator());
		privatePemFile.append("-----END PRIVATE KEY-----");

		try {
			Files.write(publicKeyPath, publicPemFile.toString().getBytes(), StandardOpenOption.CREATE,
					StandardOpenOption.TRUNCATE_EXISTING);
			Files.write(privateKeyPath, privatePemFile.toString().getBytes(), StandardOpenOption.CREATE,
					StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			throw new RuntimeException("IOException：Saving key file failure." + e.getMessage());
		}
	}

	/**
	 * 將給定的key存起來，PEM編碼儲存於預設位置
	 * 
	 * @param keyPair
	 */
	public void saveKeyPairInPEM(KeyPair keyPair) {

		Path publicKeyPath = Paths.get("publicKey.pem");
		Path privateKeyPath = Paths.get("privateKey.pem");
		saveKeyPairInPEM(keyPair, publicKeyPath, privateKeyPath);
	}

	/**
	 * 將給定的key存起來，DER編碼(二進位)儲存於指定位置
	 * 
	 * @param keyPair
	 * @param publicKeyPath  公鑰存放位置，含檔名
	 * @param privateKeyPath 私鑰存放位置，含檔名
	 */
	public void saveKeyPairInDER(KeyPair keyPair, Path publicKeyPath, Path privateKeyPath) {

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		try {
			Files.write(publicKeyPath, publicKey.getEncoded(), StandardOpenOption.CREATE,
					StandardOpenOption.TRUNCATE_EXISTING);
			Files.write(privateKeyPath, privateKey.getEncoded(), StandardOpenOption.CREATE,
					StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			throw new RuntimeException("IOException：Saving key file failure." + e.getMessage());
		}
	}

	/**
	 * 將給定的key存起來，DER編碼(二進位)儲存於預設位置
	 * 
	 * @param keyPair
	 */
	public void saveKeyPairInDER(KeyPair keyPair) {

		Path publicKeyPath = Paths.get("publicKey.pem");
		Path privateKeyPath = Paths.get("privateKey.pem");
		saveKeyPairInDER(keyPair, publicKeyPath, privateKeyPath);
	}

	/**
	 * 讀取二進位的公鑰，限定X509格式
	 * 
	 * @param publicKeyPath 讀取位置
	 * @return
	 */
	public PublicKey readDERPublicKey(Path publicKeyPath) {
		byte[] publicKeyBytes = readAllBytes(publicKeyPath);
		KeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		return generatePublic(publicKeySpec);
	}

	/**
	 * 讀取PEM格式(Base64)的公鑰，限定X509格式
	 * 
	 * @param publicKeyPath 讀取位置
	 * @return
	 */
	public PublicKey readPEMPublicKey(Path publicKeyPath) {
		StringBuilder keyBody = new StringBuilder();
		readSublines(publicKeyPath).stream().forEach(line -> {
			keyBody.append(line);
		});
		byte[] publicKeyBase64Bytes = keyBody.toString().getBytes();
		byte[] publicKeyBytes = decoder.decode(publicKeyBase64Bytes);
		KeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		return generatePublic(publicKeySpec);
	}

	/**
	 * 讀取二進位的私鑰，限定PKCS8格式
	 * 
	 * @param privateKeyPath 讀取位置
	 * @return
	 */
	public PrivateKey readDERPrivateKey(Path privateKeyPath) {
		byte[] privateKeyBytes = readAllBytes(privateKeyPath);
		KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		return generatePrivate(privateKeySpec);
	}

	/**
	 * 讀取PEM格式(Base64)的私鑰，限定PKCS8格式
	 * 
	 * @param privateKeyPath 讀取位置
	 * @return
	 */
	public PrivateKey readPEMPrivateKey(Path privateKeyPath) {
		StringBuilder keyBody = new StringBuilder();
		readSublines(privateKeyPath).stream().forEach(line -> {
			keyBody.append(line);
		});
		byte[] privateKeyBase64Bytes = keyBody.toString().getBytes();
		byte[] privateKeyBytes = decoder.decode(privateKeyBase64Bytes);
		KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		return generatePrivate(privateKeySpec);
	}

	private byte[] readAllBytes(Path path) {
		try {
			return Files.readAllBytes(path);
		} catch (IOException e) {
			throw new RuntimeException("IOException：" + e.getMessage());
		}
	}

	/**
	 * 取得去頭尾行的List
	 * 
	 * @param path
	 * @return
	 */
	private List<String> readSublines(Path path) {
		List<String> list;
		try {
			list = Files.readAllLines(path);
			return list.subList(1, list.size() - 1);
		} catch (IOException e) {
			throw new RuntimeException("IOException：" + e.getMessage());
		}
	}

	private PublicKey generatePublic(KeySpec publicKeySpec) {
		try {
			return factory.generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("InvalidKeySpecException. Maybe your key is not X509 format." + e.getMessage());
		}
	}

	private PrivateKey generatePrivate(KeySpec privateKeySpeec) {
		try {
			return factory.generatePrivate(privateKeySpeec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("InvalidKeySpecException. Maybe your key is not PKCS#8 format. " + e.getMessage());
		}
	}
}