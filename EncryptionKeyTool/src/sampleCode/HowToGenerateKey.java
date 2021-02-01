package sampleCode;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import encryption.RSAKeyUtil;

public class HowToGenerateKey {

	public static void main(String[] args) {
		
		// 先建立工具類別
		RSAKeyUtil rsaKeyUtil = new RSAKeyUtil.Builder().setKeySize(2048).build();
		// 產生一對key，分別為PKCS#8規格的私鑰與X509規格的公鑰
		KeyPair keyPair = rsaKeyUtil.generateKeyPair();
		// 儲存Key至指定位置
		Path publicKeyPath = Paths.get("src/keyLocation/public.pem");
		Path privateKeyPath = Paths.get("src/keyLocation/private.pem");
		rsaKeyUtil.saveKeyPairInPEM(keyPair, publicKeyPath, privateKeyPath);
	}
	
}
