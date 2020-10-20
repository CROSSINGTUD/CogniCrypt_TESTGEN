package de.cognicrypt.testgenerator.generator;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Set;

import de.cognicrypt.core.Constants;
import de.cognicrypt.testgenerator.test.TestClass;
import de.cognicrypt.testgenerator.test.TestProject;

public class CodeHandler {

	public File writeToDisk(TestProject testProject) throws Exception {

		File fileOnDisk = new File(testProject.getProjectPath() + Constants.innerFileSeparator + testProject.getSourcePath() + Constants.innerFileSeparator + "jca" + Constants.innerFileSeparator);
		fileOnDisk.mkdirs();
		for (TestClass toBeGeneratedClass : testProject.getTestClasses()) {
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
