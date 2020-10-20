package de.cognicrypt.testgenerator.generator;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import crypto.interfaces.ICrySLPredicateParameter;
import crypto.interfaces.ISLConstraint;
import crypto.rules.CrySLComparisonConstraint;
import crypto.rules.CrySLConstraint;
import crypto.rules.CrySLConstraint.LogOps;
import crypto.rules.CrySLObject;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.CrySLValueConstraint;
import de.cognicrypt.testgenerator.test.TestClass;

public class ConstraintResolver {

	public String analyseConstraints(Entry<String, String> parameter, CrySLRule rule, TestClass testClass) {
		List<ISLConstraint> constraints = rule.getConstraints().stream().filter(e -> e.getInvolvedVarNames().contains(parameter.getKey())).collect(Collectors.toList());
		
		for (ISLConstraint constraint : constraints) {
			// handle CrySLValueConstraint
			String value = resolveCrySLConstraint(rule, parameter, constraint);
			if (!value.isEmpty()) {
				if ("java.lang.String".equals(parameter.getValue())) {
					value = "\"" + value + "\"";
				} else if ("java.lang.String[]".equals(parameter.getValue())) {
					value = "new String[]{\"" + value + "\"}";
				} else if ("java.math.BigInteger".equals(parameter.getValue())) {
					value = "BigInteger.valueOf(" + value + ")";
					testClass.addImport("java.math.BigInteger");
				} else {
					CacheManager.ruleParameterCache.putIfAbsent(parameter.getKey(), value);
				}
				return value;
			}
		}
		return "";
	}

	private String resolveCrySLConstraint(CrySLRule rule, Entry<String, String> parameter, ISLConstraint constraint) {
		return resolveCrySLConstraint(rule, parameter, constraint, false);
	}
	
	private String resolveCrySLConstraint(CrySLRule rule, Entry<String, String> parameter, ISLConstraint constraint, boolean onlyEval) {
		String parVarName = parameter.getKey();
		if (constraint instanceof CrySLValueConstraint) {
			CrySLValueConstraint asVC = (CrySLValueConstraint) constraint;
			String constraintValue = asVC.getValueRange().get(0);
			if (onlyEval) {
				if (CacheManager.ruleParameterCache.containsKey(parVarName) && asVC.getValueRange().contains(CacheManager.ruleParameterCache.get(parVarName))) {
					return constraintValue;
				}
			} else if (asVC.getInvolvedVarNames().contains(parVarName)) {
				if ("transformation".equals(parVarName) && Arrays.asList(new String[] { "AES" }).contains(constraintValue)) {
					constraintValue += dealWithCipherGetInstance(rule);
				}
				CacheManager.ruleParameterCache.putIfAbsent(parVarName, constraintValue);
				return constraintValue;
			}
		} else if (constraint instanceof CrySLComparisonConstraint) {
			CrySLComparisonConstraint comp = (CrySLComparisonConstraint) constraint;
			if (comp.getLeft().getLeft() instanceof CrySLObject && comp.getRight().getLeft() instanceof CrySLObject) {
				CrySLObject left = (CrySLObject) comp.getLeft().getLeft();
				CrySLObject right = (CrySLObject) comp.getRight().getLeft();
				int value = Integer.MIN_VALUE;
				String varName = "";
				try {
					value = Integer.parseInt(left.getName());
					varName = right.getVarName();
				} catch (NumberFormatException ex) {
					try {
						if(right.getName().contains("^")) {
							String[] operands = right.getName().split("\\^");
							value = (int) Math.pow(Double.valueOf(operands[0]), Double.valueOf(operands[1]));
						}
						else {
							value = Integer.parseInt(right.getName());
						}
						varName = left.getVarName();
					} catch (NumberFormatException ex2) {
						return "";
					}
				}
				String secureInt = "";
				switch (comp.getOperator()) {
					case g:
					case ge:
						try {
							secureInt = String.valueOf(SecureRandom.getInstance("SHA1PRNG").nextInt(2 * value) + value);
						} catch (NoSuchAlgorithmException e1) {}
						break;
					case l:
					case le:
						try {
							secureInt = String.valueOf(SecureRandom.getInstance("SHA1PRNG").nextInt(value));
						} catch (NoSuchAlgorithmException e) {}
						break;
					case neq:
						try {
							secureInt = String.valueOf(SecureRandom.getInstance("SHA1PRNG").nextInt(value - 1));
						} catch (NoSuchAlgorithmException e) {}
						break;
					case eq:
					default:
						break;
				}
				CacheManager.parameterCache.putIfAbsent(varName, secureInt);
				return secureInt;
			}
		} else if (constraint instanceof CrySLPredicate && "instanceOf".equals(((CrySLPredicate) constraint).getPredName())) {
			List<ICrySLPredicateParameter> instanceOfPred = ((CrySLPredicate) constraint).getParameters();
			return ((CrySLObject) instanceOfPred.get(0)).getVarName();
		} else if (constraint instanceof CrySLConstraint) {

			CrySLConstraint crySLConstraint = (CrySLConstraint) constraint;
			LogOps operator = crySLConstraint.getOperator();
			ISLConstraint left = crySLConstraint.getLeft();
			ISLConstraint right = crySLConstraint.getRight();
			Entry<String, String> leftAlternative = new SimpleEntry<String, String>(left.getInvolvedVarNames().iterator().next(), parameter.getValue());
			Entry<String, String> rightAlternative = new SimpleEntry<String, String>(right.getInvolvedVarNames().iterator().next(), parameter.getValue());

			if (operator == LogOps.and) {
				if (left.getInvolvedVarNames().contains(parVarName)) {
					if (!right.getInvolvedVarNames().contains(parVarName)) {
						if (!resolveCrySLConstraint(rule, parameter, right, true).isEmpty()) {
							return resolveCrySLConstraint(rule, parameter, left);
						} else {
							return "";
						}
					} else {
						if (resolveCrySLConstraint(rule, parameter, left, true).isEmpty()) {
							return resolveCrySLConstraint(rule, parameter, right);
						} else {
							return resolveCrySLConstraint(rule, parameter, left);
						}
					}
				} else if (!resolveCrySLConstraint(rule, parameter, left).isEmpty()) {
					return resolveCrySLConstraint(rule, parameter, right);
				}
				return "";
			} else if (operator == LogOps.or) {
				if (!onlyEval) {
					if (left.getInvolvedVarNames().contains(parVarName)) {
						if (resolveCrySLConstraint(rule, parameter, left).isEmpty()) {
							if (right.getInvolvedVarNames().contains(parVarName) && !resolveCrySLConstraint(rule, parameter, right, true).isEmpty()) {
								return resolveCrySLConstraint(rule, parameter, right);
							} else {
								return "";
							}
						}
						return resolveCrySLConstraint(rule, parameter, left);
					}
					return resolveCrySLConstraint(rule, parameter, right);
				} else {
					String leftResult = resolveCrySLConstraint(rule, parameter, left, onlyEval);
					if (!leftResult.isEmpty()) {
						return leftResult;
					} else {
						return resolveCrySLConstraint(rule, rightAlternative, right, onlyEval);
					}
				}
			} else if (operator == LogOps.implies) {
				if (!right.getInvolvedVarNames().contains(parVarName) || resolveCrySLConstraint(rule, leftAlternative, left, true).isEmpty()) {
					return "";
				}
				return resolveCrySLConstraint(rule, parameter, right);
			} else {
				return ""; // invalid operator
			}
		}
		return ""; // unsupported object type
	}
	
	private String dealWithCipherGetInstance(CrySLRule rule) {
		String mode = "";
		String pad = "";
		List<ISLConstraint> constraints = rule.getConstraints().parallelStream().filter(e -> e.getInvolvedVarNames().contains("transformation"))
			.filter(e -> e instanceof CrySLConstraint && ((CrySLConstraint) e).getLeft().getName().contains("AES")).collect(Collectors.toList());
		for (ISLConstraint cons : constraints) {
			if (cons instanceof CrySLConstraint && ((CrySLConstraint) cons).getOperator() == LogOps.implies) {
				CrySLValueConstraint valCons = (CrySLValueConstraint) ((CrySLConstraint) cons).getRight();
				int pos = valCons.getVar().getSplitter().getIndex();
				if (pos == 1 && mode.isEmpty()) {
					mode = valCons.getValueRange().get(0);
				} else if (pos == 2 && pad.isEmpty()) {
					pad = valCons.getValueRange().get(0);
				}
			}
		}
		//if all fails
		if (mode.isEmpty()) {
			mode = "CBC";
		}
		if (pad.isEmpty()) {
			pad = "PKCS5Padding";
		}
		return "/" + mode + "/" + pad;
	}
}
