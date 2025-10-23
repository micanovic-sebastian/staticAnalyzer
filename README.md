## Voraussetzungen
- Java 21
- IntelliJ

## Installation
mvn clean package

## Parameter
- vt-mode=hash | zip | none 
- log=path/to/file.log | none
- standardmäßig wird eine Log-Datei erstellt und VirusTotal-Scan durchgeführt

## Ausführen
java -jar pfad\zur\datei vt-mode=param1 log=param2

## z.B Beispiel hier 
java -jar .\target\staticAnalyzer.jar .\src\main\java\org\example\test\TestClass.java 