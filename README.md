# UsefulTool
This repository is used to save my own java file.

## 公私鑰生成用工具類別
請見目錄位置：EncryptionKeyTool

創建 key 的方法可用 OpenSSL 或是利用 Java 自行建立，方法已於目錄中文件說明。

此工具除創建 key 外亦包含讀取外部 key 以及加解密字串之功能。
另外新增了對應多執行緒的修改類別 2

## RSA 加解密 GUI 工具
基於前述的公私鑰生成用工具類別製作。

Source 請見目錄位置：RSAminiTool，打包好的檔案位於 JarFile 中。

使用 JavaFX 製作，可以直接使用圖形介面操作加解密。

![](https://i.imgur.com/AE4VOV3.png)