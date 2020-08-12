package de.cognicrypt.testgenerator.generator;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Set;

import de.cognicrypt.core.Constants;
import de.cognicrypt.testgenerator.test.TestClass;

public class CodeHandler {
	
	private Set<TestClass> testClasses;

	/**
	 * constructor
	 * 
	 * @param classes
	 *        Array of file objects that include java code
	 */
	public CodeHandler(Set<TestClass> classes) {
		this.testClasses = classes;
	}

	public File writeToDisk(final String folderPath) throws Exception {

		File fileOnDisk = new File(folderPath);
		fileOnDisk.mkdirs();
		for (TestClass toBeGeneratedClass : testClasses) {
			String path = fileOnDisk.getAbsolutePath() + Constants.outerFileSeparator + toBeGeneratedClass.getClassName() + ".java";
			try (FileOutputStream fileOutputStream = new FileOutputStream(path)) {
				fileOutputStream.write(toBeGeneratedClass.toString().getBytes("UTF-8"));
			} catch (Exception e) {
				throw new Exception("Writing source code to file failed.");
			}
			toBeGeneratedClass.setSourceFile(new File(path));
		}

		return fileOnDisk;
	}
}
