package de.cognicrypt.testgenerator.test;

import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.Lists;

import de.cognicrypt.codegenerator.generator.GeneratorMethod;
import de.cognicrypt.testgenerator.utils.Utils;

public class TestMethod extends GeneratorMethod {
	
	private boolean isValid;
	
	public TestMethod(String name, boolean isValid) {
		this.name = name;
		this.isValid = isValid;
	}
	
	public void addVariablesToBody(Set<Entry<String, String>> variables) {
		addStatementToBody("");
		for (Entry<String, String> var : variables) {
			String type = var.getValue();
			String name = var.getKey();
			try {
				Class.forName(type.replaceAll("[\\[\\]]",""));
				String simpleType = Utils.retrieveOnlyClassName(type);
				addStatementToBody(simpleType + " " + name + " = null;");
			} catch (ClassNotFoundException e) {
				if(type.matches("\\w+\\[\\]")) {
					addStatementToBody(type + " " + name + " = null;");
				} else {
					addStatementToBody(type + " " + name + " = " + Utils.getDefaultValue(type) + ";");
				}
			}
		}
		addStatementToBody("");
	}
	
	public void addStatementToBody(String statement) {
		int index = -1;
		if ((index = statement.indexOf('=')) > 0) {
			String[] varDecl = statement.substring(0, index).split(" ");
			if (varDecl.length == 2) {
				SimpleEntry<String, String> newVar = new SimpleEntry<>(varDecl[1], varDecl[0]);
				if (variableDeclarations.contains(newVar)) {
					return;
				}
				variableDeclarations.add(newVar);
				String simpleVarType = Utils.retrieveOnlyClassName(newVar.getValue());
				statement = simpleVarType + " " + varDecl[1] + " = " + statement.split(" = ")[1];
			}
		}
		body.append(statement);
		body.append("\n");
	}
	
	public String toString() {
		
		String annotation = "@Test\n";
		StringBuilder method = new StringBuilder(annotation);
		String signature = modifier + " " + returnType + " " + name + "(";
		method.append(signature);
		for (int i = 0; i < getParameters().size(); i++) {
			Entry<String, String> parAtI = getParameters().get(i);
			method.append(parAtI.getValue());
			method.append(" ");
			method.append(parAtI.getKey());
			if (i < getParameters().size() - 1) {
				method.append(",");
			}
		}
		method.append(")");
		if (exceptions.size() > 0) {
			method.append(" throws ");
			List<String> exAsList = Lists.newArrayList(exceptions);
			for (int i = 0; i < exceptions.size(); i++) {
				method.append(Utils.retrieveOnlyClassName(exAsList.get(i)));
				if (i < exceptions.size() - 1) {
					method.append(", ");
				}
			}
		}

		method.append("{ \n");
		method.append(body.toString().replaceAll(",\\s+\\)", ")"));
		method.append("\n}");
		if (getKillStatements() != null) {
			return method.toString().replace("return ", getKillStatements().toString() + "\n return ");
		} else {
			return method.toString();
		}
	}

	public boolean isValid() {
		return isValid;
	}

	public void setValid(boolean isValid) {
		this.isValid = isValid;
	}
}
