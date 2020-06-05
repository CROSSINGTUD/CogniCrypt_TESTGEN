package de.cognicrypt.testgenerator.generator;

import de.cognicrypt.codegenerator.generator.GeneratorClass;
import de.cognicrypt.codegenerator.generator.GeneratorMethod;

public class GeneratorTestClass extends GeneratorClass {

	public String toString() {
		StringBuilder classContent = new StringBuilder("package ");
		classContent.append(getPackageName());
		classContent.append(";\n");
		for (String impo : getImports()) {
			classContent.append("import ");
			classContent.append(impo);
			classContent.append(";\n");
		}
		classContent.append("\n");
		classContent.append(getModifier() + " class " + getClassName() + " {\n");

		for (GeneratorMethod genMeth : getMethods()) {
			classContent.append("@Test\n");
			classContent.append(genMeth);
			classContent.append("\n");
		}

		classContent.append("}");
		return classContent.toString();
	}
}
