package de.cognicrypt.testgenerator.test;

import java.util.List;
import java.util.Set;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import de.cognicrypt.codegenerator.generator.GeneratorClass;
import de.cognicrypt.codegenerator.generator.GeneratorMethod;
import de.cognicrypt.testgenerator.utils.Constants;
import de.cognicrypt.testgenerator.utils.Utils;

public class TestClass extends GeneratorClass {
	
	private int numberOfValidTestCases;
	private int numberOfInvalidTestCases;
	
	public TestClass(String name) {
		this.className = name;
		this.imports = Sets.newHashSet(Constants.TEST_IMPORTS);
		this.methods = overriddenMethods();
	}

	private List<GeneratorMethod> overriddenMethods() {
		GeneratorMethod method = new GeneratorMethod();
		method.setModifier("protected");
		method.setReturnType("Ruleset");
		method.setName("getRuleSet");
		method.addStatementToBody("return Ruleset.JavaCryptographicArchitecture;");
		return Lists.newArrayList(method);
	}
	
	public String toString() {
		StringBuilder classContent = new StringBuilder("package ");
		classContent.append(this.packageName);
		classContent.append(";\n");
		for (String impo : this.imports) {
			classContent.append("import ");
			classContent.append(impo);
			classContent.append(";\n");
		}
		classContent.append("\n");
		classContent.append(this.modifier + " class " + this.className + "Test" + " extends UsagePatternTestingFramework {\n");

		for (GeneratorMethod genMeth : this.methods) {
			classContent.append(genMeth);
			classContent.append("\n");
		}

		classContent.append("}");
		return classContent.toString();
	}

	public TestMethod addTestMethod(boolean isValid) { // Final Format : cipherCorrectTest1, cipherIncorrectTest1 ...
		
		String name = Character.toLowerCase(this.className.charAt(0)) + this.className.substring(1);
		if(isValid)
			name  += "ValidTest" + ++this.numberOfValidTestCases;
		else
			name += "InvalidTest" + ++this.numberOfInvalidTestCases;
		
		TestMethod testMethod = new TestMethod(name, isValid);
		testMethod.setModifier("public");
		testMethod.setReturnType("void");
		this.methods.add(testMethod);
		return testMethod;
	}
	
	@Override
	public String getClassName() {
		return super.getClassName() + "Test";
	}
	
	public void addImports(Set<String> imports) {
		for (String imp : imports) {
			addImport(imp);
		}
	}
	
	public void addImport(String imp) {
		imp = Utils.preprocessImports(imp);
		this.imports.add(imp);
	}
}
