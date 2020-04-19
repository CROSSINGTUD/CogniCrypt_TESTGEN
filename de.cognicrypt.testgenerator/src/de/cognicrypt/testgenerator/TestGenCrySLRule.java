package de.cognicrypt.testgenerator;

import java.util.List;
import java.util.Map.Entry;

import crypto.interfaces.ISLConstraint;
import crypto.rules.CryptSLForbiddenMethod;
import crypto.rules.CryptSLPredicate;
import crypto.rules.CryptSLRule;
import crypto.rules.StateMachineGraph;

// FIXME2 This class is not yet used. Delete if not required

public class TestGenCrySLRule extends CryptSLRule {

	public TestGenCrySLRule(String _className, List<Entry<String, String>> defObjects,
			List<CryptSLForbiddenMethod> _forbiddenMethods, StateMachineGraph _usagePattern,
			List<ISLConstraint> _constraints, List<CryptSLPredicate> _predicates) {
		super(_className, defObjects, _forbiddenMethods, _usagePattern, _constraints, _predicates);
	}

	@Override
	public boolean equals(Object rule) {
		return this.getClassName().equals(((CryptSLRule)rule).getClassName());
	}
	
	@Override
	public String getClassName() {
		String[] values = this.getClassName().split("\\.");
		return values[values.length-1];
	}
}
