package de.cognicrypt.testgenerator;

import java.util.List;
import java.util.Map.Entry;

import crypto.interfaces.ISLConstraint;
import crypto.rules.CrySLForbiddenMethod;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.StateMachineGraph;

// FIXME2 This class is not yet used. Delete if not required

public class TestGenCrySLRule extends CrySLRule {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7858343772236591849L;

	public TestGenCrySLRule(String _className, List<Entry<String, String>> defObjects,
			List<CrySLForbiddenMethod> _forbiddenMethods, StateMachineGraph _usagePattern,
			List<ISLConstraint> _constraints, List<CrySLPredicate> _predicates) {
		super(_className, defObjects, _forbiddenMethods, _usagePattern, _constraints, _predicates);
	}

	@Override
	public boolean equals(Object rule) {
		return this.getClassName().equals(((CrySLRule)rule).getClassName());
	}
	
	@Override
	public String getClassName() {
		String[] values = this.getClassName().split("\\.");
		return values[values.length-1];
	}
}
