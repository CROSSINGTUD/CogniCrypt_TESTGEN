package de.cognicrypt.testgenerator.generator;

import java.util.List;

import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import de.cognicrypt.testgenerator.test.TestMethod;

public class TestOracle {
	
	CrySLRule rule;
	TestMethod testMethod;
	
	public TestOracle(CrySLRule rule, TestMethod testMethod) {
		this.rule = rule;
		this.testMethod = testMethod;
	}

	public void generateAssertions() {
		generatePredicateAssertions();
		List<String> killStmts = TestGenerator.kills.get(rule);	
		for (String stmt : killStmts) {
			testMethod.addStatementToBody(stmt);
		}
		generateStateAssertions();
		TestGenerator.instancesCache.pop();
	}

	private void generateStateAssertions() {
//		String simpleClassName = Utils.retrieveOnlyClassName(rule.getClassName());
		String instanceName = TestGenerator.retrieveInstanceName();

		if (testMethod.isValid()) {
			testMethod.addStatementToBody("Assertions.mustBeInAcceptingState(" + instanceName + ");");
		} else {
			testMethod.addStatementToBody("Assertions.mustNotBeInAcceptingState(" + instanceName + ");");
		}
	}
	
	private void generatePredicateAssertions() {
		if(TestGenerator.ensuredValues != null) {
			CrySLPredicate predicate = TestGenerator.ensuredValues.getKey();
			String param = predicate.getParameters().get(0).getName();
//			String simpleClassName = Utils.retrieveOnlyClassName(rule.getClassName());
			String instanceName = TestGenerator.retrieveInstanceName();
			
			if (TestGenerator.ensuredValues.getValue()) {
				if(param.equals("this"))
					testMethod.addStatementToBody("Assertions.hasEnsuredPredicate(" + instanceName + ");");
				else
					testMethod.addStatementToBody("Assertions.hasEnsuredPredicate(" + param + ");");
			} else {
				if(param != null) {
					if(param.equals("this"))
						testMethod.addStatementToBody("Assertions.notHasEnsuredPredicate(" + instanceName + ");");
					else
						testMethod.addStatementToBody("Assertions.notHasEnsuredPredicate(" + param + ");");
				}
			}
		}
	}
}
