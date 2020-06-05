package de.cognicrypt.testgenerator.generator;

import java.util.List;
import java.util.Map.Entry;

import de.cognicrypt.codegenerator.generator.GeneratorMethod;
import de.cognicrypt.testgenerator.utils.TestUtils;
import de.cognicrypt.utils.Utils;

public class GeneratorTest extends GeneratorMethod {
	
	public void addVariablesToBody(List<Entry<String, String>> variables) {
		for (Entry<String, String> var : variables) {
			String type = var.getValue();
			String name = var.getKey();
			try {
				Class.forName(type);
				String simpleType = Utils.retrieveOnlyClassName(type);
				addStatementToBody(simpleType + " " + name + " = null;");
			} catch (ClassNotFoundException e) {
				if(type.matches("\\w+\\[\\]")) {
					addStatementToBody(type + " " + name + " = null;");
				} else {
					addStatementToBody(type + " " + name + " = " + TestUtils.getDefaultValue(type) + ";");
				}
			}
		}
	}
}
