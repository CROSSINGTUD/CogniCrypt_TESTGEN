package de.cognicrypt.testgenerator.generator;

import java.util.List;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import de.cognicrypt.codegenerator.generator.GeneratorMethod;
import de.cognicrypt.testgenerator.utils.TestUtils;
import de.cognicrypt.utils.Utils;

public class GeneratorTestMethod extends GeneratorMethod {
	
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
	
	public void addStatementToBody(String statement) {
		int index = -1;
		if ((index = statement.indexOf('=')) > 0) {
			String[] varDecl = statement.substring(0, index).split(" ");
			if (varDecl.length == 2) {
				SimpleEntry<String, String> newVar = new SimpleEntry<>(varDecl[1], varDecl[0]);
				if (!getDeclaredVariables().contains(newVar)) {
					getDeclaredVariables().add(newVar);
				}
				String simpleVarType = Utils.retrieveOnlyClassName(newVar.getValue());
				statement = simpleVarType + " " + varDecl[1] + " = " + statement.split(" = ")[1];
			}
		}
		body.append(statement);
		body.append("\n");
	}
}
