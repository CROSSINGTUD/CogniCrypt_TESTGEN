package de.cognicrypt.testgenerator.generator;

import java.util.List;
import java.util.Map.Entry;

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

	public void generateAssertions(boolean isExplicit) {
		generatePredicateAssertions();
		generateStateAssertions();
		deleteInstance();
		
		// generating objects with kill statements along with assertions
		if(isExplicit) {
			for (Entry<CrySLRule, Entry<List<String>, String>> entries : CacheManager.kills.entrySet()) {
					CrySLRule cRule = entries.getKey();
					Entry<List<String>, String> killStmts = entries.getValue();
					for (String stmt : killStmts.getKey())
						testMethod.addStatementToBody(stmt);
					generateStateAssertions(killStmts.getValue(), ((cRule==rule) ? true : false));
			}
		}
	}

	public void deleteInstance() {
		CacheManager.instancesCache.pop();
	}

	private void generateStateAssertions() {
		// skipping assertions for object with kill statements
		if(CacheManager.kills.containsKey(rule))
			return;
		
		String instanceName = TestGenerator.retrieveInstanceName();

		if (testMethod.isValid()) {
			testMethod.addStatementToBody("Assertions.mustBeInAcceptingState(" + instanceName + ");");
		} else {
			testMethod.addStatementToBody("Assertions.mustNotBeInAcceptingState(" + instanceName + ");");
		}
	}
	
	private void generateStateAssertions(String instanceName, boolean isExplicit) {

		if (testMethod.isValid() || !isExplicit) {
			testMethod.addStatementToBody("Assertions.mustBeInAcceptingState(" + instanceName + ");");
		} else {
			testMethod.addStatementToBody("Assertions.mustNotBeInAcceptingState(" + instanceName + ");");
		}
	}
	
	private void generatePredicateAssertions() {
		if(CacheManager.ensuredValues != null) {
			CrySLPredicate predicate = CacheManager.ensuredValues.getKey();
			String param = predicate.getParameters().get(0).getName();
			String instanceName = TestGenerator.retrieveInstanceName();
			
			if (CacheManager.ensuredValues.getValue()) {
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
