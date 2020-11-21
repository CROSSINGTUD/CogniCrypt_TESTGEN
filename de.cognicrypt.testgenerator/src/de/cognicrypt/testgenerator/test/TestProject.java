package de.cognicrypt.testgenerator.test;

import java.util.Set;

import org.eclipse.core.runtime.CoreException;

import com.google.common.collect.Sets;

import de.cognicrypt.testgenerator.Activator;
import de.cognicrypt.testgenerator.generator.CodeHandler;

public class TestProject {

	private Set<TestClass> testClasses = Sets.newHashSet();

	public void addTestClass(TestClass testClass) {
		this.testClasses.add(testClass);
	}

	public Set<TestClass> getTestClasses() {
		return testClasses;
	}

	public TestProject(String name) {
		try {
			CodeHandler.createJavaProject(name);
		} catch (CoreException e) {
			Activator.getDefault().logError(e, "Failed to create test project.");
		}
	}

	public int numberOfTestMethods() {
		int total = 0;
		for (TestClass testClass : testClasses) {
			total += testClass.getMethods().stream().filter(m -> m instanceof TestMethod).count();
		}
		return total;
	}

	public int numberOfTestClasses() {
		return testClasses.size();
	}
}
