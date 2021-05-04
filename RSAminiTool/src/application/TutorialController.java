package application;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.ResourceBundle;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.TextArea;

public class TutorialController implements Initializable {

	@FXML
	private TextArea textAreaTutorial;

	/* 說明檔位置 */
	private Path tutorialPath;

	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {

		if (tutorialPath == null) {
			try {
				tutorialPath = Paths.get(getClass().getResource("/utility/利用OpenSSL建立公私鑰.txt").toURI());
				List<String> text = Files.readAllLines(tutorialPath);
				text.forEach(t -> {
					textAreaTutorial.appendText(t + System.lineSeparator());
				});
				textAreaTutorial.setScrollTop(0);
			} catch (URISyntaxException | IOException e) {
				textAreaTutorial.setText(e.getClass() + "：" + e.getMessage());
			}
		}
	}

}
