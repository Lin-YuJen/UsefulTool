package application;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ResourceBundle;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;
import utility.EncryptionUtil;
import utility.RSAKeyUtil;

public class Controller implements Initializable {

	// 注意：需於fxml文件中，使用fx:id表示其名稱，不是使用id
	@FXML
	private Button btnClickPublic, btnClickPrivate;
	@FXML
	private Button btnKeySize512, btnKeySize1024, btnKeySize2048;
	@FXML
	private Button btnEecryption, btnDecryption;

	@FXML
	private RadioButton radioBtnPublicPEM, radioBtnPublicDER, radioBtnPrivatePEM, radioBtnPrivateDER;

	@FXML
	private ToggleGroup publicKeyFormat, privateKeyFormat;

	@FXML
	private TextField textFieldPublicKeyLocation, textFieldPrivateKeyLocation;
	@FXML
	private TextField textFieldKeySize;
	@FXML
	private TextField resultMessage;

	@FXML
	private TextArea textAreaInput, textAreaOutput;

	private RSAKeyUtil keyUtil;
	private EncryptionUtil encryptionUtil;
	private int keySize;

	private ExtensionFilter pemFilter, derFilter;

	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {
		// 初始化可以不用寫也無所謂
		keyUtil = new RSAKeyUtil.Builder().build(); // 僅用於讀取key，此處不設定keySize;
		// 副檔名過濾
		pemFilter = new ExtensionFilter("Privacy Enhanced Mail (*.pem)", "*.pem");
		derFilter = new ExtensionFilter("Distinguished Encoding Rules (*.der)", "*.der");
		keySize = Integer.valueOf(textFieldKeySize.getText());

		Path publicKeyPath = Paths.get(System.getProperty("user.home"), "Desktop", "publicKey.pem");
		if (Files.exists(publicKeyPath)) {
			textFieldPublicKeyLocation.setText(publicKeyPath.toString());
		}
		Path privateKeyPath = Paths.get(System.getProperty("user.home"), "Desktop", "/privateKey.pem");
		if (Files.exists(privateKeyPath)) {
			textFieldPrivateKeyLocation.setText(privateKeyPath.toString());
		}
		File publicKeyFile = new File("publicKey.pem");
		File privateKeyFile = new File("privateKey.pem");
		if(publicKeyFile.exists()) {
			textFieldPublicKeyLocation.setText(publicKeyFile.getAbsolutePath());
		}
		if(privateKeyFile.exists()) {
			textFieldPrivateKeyLocation.setText(privateKeyFile.getAbsolutePath());
		}
	}

	@FXML
	public void getPublicKeyLocation(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open PublicKey File");
		fileChooser.getExtensionFilters().add(pemFilter);
		fileChooser.getExtensionFilters().add(derFilter);
		fileChooser.setInitialDirectory(new File(System.getProperty("user.home") + "/Desktop"));
		File file = fileChooser.showOpenDialog(new Stage());
		textFieldPublicKeyLocation.setText(file == null ? "No file has been selected." : file.toString());
	}

	@FXML
	public void getPrivateKeyLocation(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open PrivateKey File");
		fileChooser.getExtensionFilters().add(pemFilter);
		fileChooser.getExtensionFilters().add(derFilter);
		fileChooser.setInitialDirectory(new File(System.getProperty("user.home") + "/Desktop"));
		File file = fileChooser.showOpenDialog(new Stage());
		textFieldPrivateKeyLocation.setText(file == null ? "No file has been selected." : file.toString());
	}

	@FXML
	public void changeKeySize512(ActionEvent event) {
		textFieldKeySize.setText("512");
		keySize = 512;
	}

	@FXML
	public void changeKeySize1024(ActionEvent event) {
		textFieldKeySize.setText("1024");
		keySize = 1024;
	}

	@FXML
	public void changeKeySize2048(ActionEvent event) {
		textFieldKeySize.setText("2048");
		keySize = 2048;
	}

	@FXML
	public void doDecryption(ActionEvent event) {
		String path = textFieldPrivateKeyLocation.getText();
		File file = new File(path);
		if (!file.isFile()) {
			resultMessage.setText("Fail to read private key file.");
			return;
		}
		RadioButton selectedRadioButton = (RadioButton) privateKeyFormat.getSelectedToggle();
		PrivateKey privateKey;
		try {
			if (selectedRadioButton.getText().startsWith("PEM")) {
				privateKey = keyUtil.readPEMPrivateKey(file.toPath());
			} else {
				privateKey = keyUtil.readDERPrivateKey(file.toPath());
			}
			encryptionUtil = new EncryptionUtil.Builder().setAlgorithm("RSA").setKeySize(keySize)
					.setPrivateKey(privateKey).build();
			String input = textAreaInput.getText();
			String output = encryptionUtil.decryptInStringByPrivateKey(input);
			textAreaOutput.setText(output);
			resultMessage.setText("");
		} catch (Exception e) {
			textAreaOutput.setText("");
			resultMessage.setText(e.getMessage());
		}
	}

	@FXML
	public void doEecryption(ActionEvent event) {
		String path = textFieldPublicKeyLocation.getText();
		File file = new File(path);
		if (!file.isFile()) {
			resultMessage.setText("Fail to read public key file.");
			return;
		}
		RadioButton selectedRadioButton = (RadioButton) publicKeyFormat.getSelectedToggle();
		PublicKey publicKey;
		try {
			if (selectedRadioButton.getText().startsWith("PEM")) {
				publicKey = keyUtil.readPEMPublicKey(file.toPath());
			} else {
				publicKey = keyUtil.readDERPublicKey(file.toPath());
			}
			encryptionUtil = new EncryptionUtil.Builder().setAlgorithm("RSA").setKeySize(keySize)
					.setPublicKey(publicKey).build();
			String input = textAreaInput.getText();
			String output = encryptionUtil.encryptInStringByPublicKey(input);
			textAreaOutput.setText(output);
			resultMessage.setText("");
		} catch (Exception e) {
			textAreaOutput.setText("");
			resultMessage.setText(e.getMessage());
		}
	}

	@FXML
	public void exchangeContent(ActionEvent event) {
		String inputContent = textAreaInput.getText();
		String outputContent = textAreaOutput.getText();
		String temp = inputContent;
		textAreaInput.setText(outputContent);
		textAreaOutput.setText(temp);
	}

	@FXML
	public void resetInputAndOutput(ActionEvent event) {
		textAreaInput.setText("");
		textAreaOutput.setText("");
		resultMessage.setText("");
	}

	@FXML
	public void howToGetRSAKeyByOpenSSL(ActionEvent event) {

		Parent root;
		try {
			root = FXMLLoader.load(getClass().getResource("/application/tutrialScene.fxml"));
			Stage stage = new Stage();
			stage.setTitle("RSA 加解密小工具");
			stage.setResizable(false);
			stage.setScene(new Scene(root));
			stage.show();
		} catch (IOException e) {
			resultMessage.setText(e.getClass() + "：" + e.getMessage());
		}
	}

}
