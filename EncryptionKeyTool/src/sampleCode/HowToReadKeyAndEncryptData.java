package sampleCode;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

import encryption.EncryptionUtil;
import encryption.RSAKeyUtil;

public class HowToReadKeyAndEncryptData {

	public static void main(String[] args) {

		// 指定讀取位置
		Path publicKeyPath = Paths.get("src/keyLocation/publicKey.pem");
		Path privateKeyPath = Paths.get("src/keyLocation/privateKey.pem");
		// 先建立工具類別
		RSAKeyUtil rsaKeyUtil = new RSAKeyUtil.Builder().setKeySize(2048).build();
		// 讀取後可建立key物件，注意只限定PKCS#8的私鑰與X509的公鑰
		// OpenSSL產生的私鑰是PKCS#1，必須先轉換過方可使用
		PrivateKey privateKey = rsaKeyUtil.readPEMPrivateKey(privateKeyPath);
		PublicKey publicKey = rsaKeyUtil.readPEMPublicKey(publicKeyPath);
		
		// 建立加密工具類別，
		EncryptionUtil encryptionUtil = new EncryptionUtil.Builder().setPrivateKey(privateKey).setPublicKey(publicKey)
				.setAlgorithm("RSA").setKeySize(2048).build();
		
		// 加解密用法如下：
		String message = "hello youtube.";
		System.out.println("OriginalMessage is ====\n"+message);
		String encryptedMessage = encryptionUtil.encryptInStringByPublicKey(message);
		System.out.println("encryptedMessage is ====\n" + encryptedMessage);
		String decryptedMessage = encryptionUtil.decryptInStringByPrivateKey(encryptedMessage);
		System.out.println("decryptedMessage is ====\n"+decryptedMessage);
		
	}
}
