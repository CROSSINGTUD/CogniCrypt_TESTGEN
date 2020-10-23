package de.cognicrypt.testgenerator.generator;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.AbstractMap.SimpleEntry;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.Map.Entry;
import java.util.Optional;

import com.google.common.collect.Lists;

import crypto.interfaces.ISLConstraint;
import crypto.rules.CrySLMethod;
import crypto.rules.CrySLObject;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.TransitionEdge;
import de.cognicrypt.testgenerator.Activator;
import de.cognicrypt.testgenerator.test.TestClass;
import de.cognicrypt.testgenerator.test.TestMethod;
import de.cognicrypt.testgenerator.utils.Utils;

public class ParameterResolver {
	
	PredicateConnectionsHandler predicatesHandler;
	TestGenerator testGenerator;
	
	public ParameterResolver(PredicateConnectionsHandler predicatesHandler, TestGenerator testGenerator) {
		this.predicatesHandler = predicatesHandler;
		this.testGenerator = testGenerator;
	}

	Entry<String, List<Entry<String, String>>> replaceParameterByValue(CrySLRule rule,
			TestMethod testMethod, TestClass testClass, String currentInvokedMethod, CrySLMethod crySLMethod) {

		String methodNamdResultAssignment = currentInvokedMethod.substring(0, currentInvokedMethod.indexOf("("));
		String methodParameter = currentInvokedMethod.substring(currentInvokedMethod.indexOf("("), currentInvokedMethod.indexOf(")"));
		String appendix = currentInvokedMethod.substring(currentInvokedMethod.indexOf(")"), currentInvokedMethod.length());
		List<Entry<String, String>> variablesToBeAdded = Lists.newArrayList();
		List<Entry<String, String>> declaredVariables = testMethod.getDeclaredVariables();
		List<Entry<String, String>> parametersOfCall = crySLMethod.getParameters();

		methodParameter = resolveVoidTypes(crySLMethod, methodParameter, testClass);

		for (Entry<String, String> parameter : parametersOfCall) {

			// STEP 1 : check if any of the declared variables match the parameter
			//			Optional<Entry<String, String>> typeMatch = declaredVariables.stream()
			//				.filter(e -> (Utils.isSubType(e.getValue(), parameter.getValue()) || Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
			//			if (typeMatch.isPresent()) {
			////				updateToBeEnsured(typeMatch.get());
			//				methodParameter = methodParameter.replace(parameter.getKey(), typeMatch.get().getKey());
			//				continue;
			//			}

			// STEP 2 : check if parameter can be ensured by any of the predicate connections
			Optional<ISLConstraint> requiredPreds = rule.getConstraints().stream().filter(e -> 
			e instanceof CrySLPredicate && e.getInvolvedVarNames().contains(parameter.getKey())).findFirst();
			if(requiredPreds.isPresent()) {
				Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> producer = predicatesHandler.getPredicateConnections().stream()
						.filter(e -> {
							if(Utils.isSubType(e.getValue().getValue().getClassName(), rule.getClassName()) || Utils.isSubType(rule.getClassName(), e.getValue().getValue().getClassName())) {
								final CrySLObject crySLObject = (CrySLObject) e.getKey().getParameters().get(0);
								// why is this required?
								return Utils.isSubType(crySLObject.getJavaType(), parameter.getValue()) || Utils.isSubType(parameter.getValue(), crySLObject.getJavaType());
							}
							return false;
						})
						.findFirst();

				if(producer.isPresent()) {

					Collections.reverse(declaredVariables);
					Optional<Entry<String, String>> preMatch = declaredVariables.stream()
							.filter(e -> (Utils.isSubType(e.getValue(), parameter.getValue()) || Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
					if (preMatch.isPresent()) {
						methodParameter = methodParameter.replace(parameter.getKey(), preMatch.get().getKey());
						continue;
					}

					Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> temp = CacheManager.toBeEnsuredPred; 
					CacheManager.toBeEnsuredPred = producer.get();
					final CrySLRule producerRule = (CrySLRule) producer.get().getValue().getKey();
					FSMHandler fsmHandler = new FSMHandler(producerRule.getUsagePattern());
					List<TransitionEdge> validTransitions = fsmHandler.getValidTransitionFromStateMachine(false);
					if(!testMethod.isValid()) {
						// even for invalid tests the method invocations are generated correctly for implicit rules
						testMethod.setValid(true);
						testGenerator.generateTest(producerRule, testClass, validTransitions, testMethod, false);
						testMethod.setValid(false);
					} else {
						testGenerator.generateTest(producerRule, testClass, validTransitions, testMethod, false);
					}
					CacheManager.toBeEnsuredPred = temp;

					Collections.reverse(declaredVariables);
					Optional<Entry<String, String>> postMatch = declaredVariables.stream()
							.filter(e -> (Utils.isSubType(e.getValue(), parameter.getValue()) || Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
					if (postMatch.isPresent()) {
						//						updateToBeEnsured(match.get());
						methodParameter = methodParameter.replace(parameter.getKey(), postMatch.get().getKey());
					}
					continue;
				}
			}

			// STEP 3 : check if parameter can be generated by analysing CONSTRAINTS of the corresponding CrySL rule
			ConstraintResolver constraintResolver = new ConstraintResolver();
			String value = constraintResolver.analyseConstraints(parameter, rule, testClass);
			if (!value.isEmpty()) {
				// NOTE2 what if a method has two parameter both of which can be resolved from using CONSTRAINTS, then in that case wouldn't methodParameter overwritten?
				String pattern = "(\\(|,| )" + parameter.getKey() + "(,| |$)";
				String replaceValue = "$1" + value + "$2";
				methodParameter = methodParameter.replaceAll(pattern, replaceValue);
				continue;
			}

			// STEP 4 : If everything fails, then it add the parameter as declared variables in the test method
			if(!parameter.getValue().equals("AnyType")) {
				variablesToBeAdded.add(parameter);
				String paramType = parameter.getValue();
				if (paramType.contains(".")) {
					testClass.addImport(paramType);
				}	
			}
		}

		currentInvokedMethod = methodNamdResultAssignment + methodParameter + appendix;
		return new SimpleEntry<>(currentInvokedMethod, variablesToBeAdded);
	}

	private String resolveVoidTypes(CrySLMethod crySLMethod, String methodParameter, TestClass testClass) {

		List<Entry<String, String>> parametersOfCall = crySLMethod.getParameters();
		if(parametersOfCall.contains(new SimpleEntry<>("_", "AnyType"))) {
			Class<?>[] cryslMethodParameters = Utils.collectParameterTypes(crySLMethod.getParameters());
			String className = crySLMethod.getMethodName().substring(0, crySLMethod.getMethodName().lastIndexOf("."));
			String methodName = crySLMethod.getShortMethodName();
			Parameter[] originalMethodParameters = null;
			try {
				Method[] methods = Class.forName(className).getMethods();
				for (Method meth : methods) {
					if (meth.getName().equals(methodName) && cryslMethodParameters.length == meth.getParameterCount()) {
						if (Utils.matchMethodParameters(cryslMethodParameters, meth.getParameterTypes())) {
							originalMethodParameters = meth.getParameters();
							break;
						}
					}
				}
				if(originalMethodParameters == null) {
					Constructor[] constructors = Class.forName(className).getConstructors();
					for (Constructor cons: constructors) {
						String fullyQualifiedName = cons.getName();
						String consName = Utils.retrieveOnlyClassName(fullyQualifiedName);
						if (consName.equals(methodName) && cryslMethodParameters.length == cons.getParameterCount()) {
							if (Utils.matchMethodParameters(cryslMethodParameters, cons.getParameterTypes())) {
								originalMethodParameters = cons.getParameters();
								break;
							}
						}
					}
				}
			} catch (SecurityException | ClassNotFoundException e) {
				Activator.getDefault().logError(e, "Unable to resolve void type.");
			}

			ListIterator<Entry<String, String>> itr = parametersOfCall.listIterator();
			while(itr.hasNext()) {
				if(itr.next().getValue().equals("AnyType")) {
					String resolvedType = originalMethodParameters[itr.previousIndex()].getType().getCanonicalName();
					methodParameter = methodParameter.replaceFirst("_", "(" + Utils.retrieveOnlyClassName(resolvedType) + ") null");
					if (resolvedType.contains(".")) {
						testClass.addImport(resolvedType);
					}
				}
			}
		}
		return methodParameter;
	}
}
