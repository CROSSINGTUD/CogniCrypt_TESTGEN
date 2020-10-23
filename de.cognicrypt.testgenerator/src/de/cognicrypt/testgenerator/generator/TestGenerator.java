package de.cognicrypt.testgenerator.generator;

import java.util.AbstractMap.SimpleEntry;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.core.runtime.CoreException;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import crypto.interfaces.ICrySLPredicateParameter;
import crypto.rules.CrySLCondPredicate;
import crypto.rules.CrySLMethod;
import crypto.rules.CrySLObject;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.StateNode;
import crypto.rules.TransitionEdge;
import de.cognicrypt.testgenerator.Activator;
import de.cognicrypt.testgenerator.test.TestClass;
import de.cognicrypt.testgenerator.test.TestMethod;
import de.cognicrypt.testgenerator.test.TestProject;
import de.cognicrypt.testgenerator.utils.Constants;
import de.cognicrypt.testgenerator.utils.CrySLUtils;
import de.cognicrypt.testgenerator.utils.Utils;

public class TestGenerator {

	private static final Logger LOGGER = Logger.getLogger(TestGenerator.class.getName());
	
	private TestProject testProject;
	private List<CrySLRule> rules;
	private PredicateConnectionsHandler predicatesHandler;
	
	private static TestGenerator instance;
	public static MODE STRATEGY = MODE.IS_SELECT_ALL;
	public static CrySLMethod selectedMethod;
	
	public static enum MODE {
		IS_SELECT_FIRST,
		IS_SELECT_RANDOM,
		IS_SELECT_ALL
	}

	private TestGenerator() {
		LOGGER.setLevel(Level.INFO);
		LOGGER.info("Reading ruleset.");
		rules = CrySLUtils.readCrySLRules();
		LOGGER.info("Finished reading ruleset.");
		if(!rules.isEmpty()) {
			testProject = new TestProject(Constants.PROJECT_NAME);
		} else {
			LOGGER.info("No rules detected.");
			return;
		}
		predicatesHandler = new PredicateConnectionsHandler(rules);
//		predicatesHandler.printPredicateConnections();
	}

	public static TestGenerator getInstance() {
		if (TestGenerator.instance == null) {
			TestGenerator.instance = new TestGenerator();
		}
		return TestGenerator.instance;
	}

	public void generateTests() {
		
		List<String> selectedRules = Utils.getSelectedRules(); 
		
		Iterator<CrySLRule> ruleIterator = rules.iterator();
		while (ruleIterator.hasNext()) {
			CrySLRule curRule = ruleIterator.next();
//			if(curRule.getClassName().equals("java.security.SecureRandom")) {
			if(selectedRules.contains(curRule.getClassName())) {
				LOGGER.info("Creating tests for " + curRule.getClassName());
				String simpleClassName = Utils.retrieveOnlyClassName(curRule.getClassName());
				TestClass testClass = new TestClass(simpleClassName);
				testProject.addTestClass(testClass);
				
//				Map<String, List<CrySLPredicate>> reliablePreds = Maps.newHashMap();

				CacheManager.ruleParameterCache.clear();
				// valid test cases
				generateValidTests(curRule, testClass);
				
				// invalid test cases
				generateInvalidTests(curRule, testClass);
			}
		}
		writeToDisk(testProject);
		cleanProject();
		LOGGER.info("Total rules covered : " + testProject.numberOfTestClasses());
		LOGGER.info("Total test cases generated : " + testProject.numberOfTestMethods());
	}

	private void writeToDisk(TestProject testProject) {
		CodeHandler codeHandler = new CodeHandler();
		try {
			codeHandler.writeToDisk(testProject);
		} catch (Exception e) {
			Activator.getDefault().logError(e, "Failed to write to disk.");
		}
	}

	private void cleanProject() {
		LOGGER.info("Cleaning up generated project.");
		try {
			testProject.cleanUpProject();
		} catch (CoreException e) {
			Activator.getDefault().logError(e, "Failed to clean up.");
		}
		LOGGER.info("Finished clean up.");
	}

	private void generateInvalidTests(CrySLRule curRule, TestClass testClass) {
		FSMHandler fsmHandler = new FSMHandler(curRule.getUsagePattern());
		Iterator<List<TransitionEdge>> invalidTransitions = fsmHandler.getInvalidTransitionsFromStateMachine();
		if(TestGenerator.STRATEGY == MODE.IS_SELECT_FIRST || TestGenerator.STRATEGY == MODE.IS_SELECT_RANDOM) {
			while(invalidTransitions.hasNext()) {
				List<TransitionEdge> currentTransition = invalidTransitions.next();
				TestMethod testMethod = testClass.addTestMethod(false);
				CacheManager.instancesCache.clear();
				generateTest(curRule, testClass, currentTransition, testMethod, true);
			}
		} else if(TestGenerator.STRATEGY == MODE.IS_SELECT_ALL) {
			while(invalidTransitions.hasNext()) {
				List<TransitionEdge> currentTransition = invalidTransitions.next();
				
				for(TransitionEdge edge : currentTransition) {
					int numberOfLabels = edge.getLabel().size();
					if(numberOfLabels > 1) {
						List<CrySLMethod> labels;
						// this condition avoids redundant invalid test cases
						if(currentTransition.get(0).equals(edge))
							labels = edge.getLabel();
						else
							labels = edge.getLabel().subList(1, numberOfLabels);
						for(CrySLMethod method : labels) {
							selectedMethod = method;
							TestMethod testMethod = testClass.addTestMethod(false);
							CacheManager.instancesCache.clear();
							generateTest(curRule, testClass, currentTransition, testMethod, true);
						}
					}
				}
			}
		}
	}

	private void generateValidTests(CrySLRule curRule, TestClass testClass) {
//		Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> toBeEnsured = determineEnsurePreds(curRule);
		FSMHandler fsmHandler = new FSMHandler(curRule.getUsagePattern());
		Iterator<List<TransitionEdge>> validTransitions = fsmHandler.getValidTransitionsFromStateMachine();
		if(TestGenerator.STRATEGY == MODE.IS_SELECT_FIRST || TestGenerator.STRATEGY == MODE.IS_SELECT_RANDOM) {
			while(validTransitions.hasNext()) {
				List<TransitionEdge> currentTransition = validTransitions.next();
				TestMethod testMethod = testClass.addTestMethod(true);
				CacheManager.instancesCache.clear();
				generateTest(curRule, testClass, currentTransition, testMethod, true);
			}
		} else if(TestGenerator.STRATEGY == MODE.IS_SELECT_ALL) {
			while(validTransitions.hasNext()) {
				List<TransitionEdge> currentTransition = validTransitions.next();
				
				for(TransitionEdge edge : currentTransition) {
					int numberOfLabels = edge.getLabel().size();
					if(numberOfLabels > 1) {
						List<CrySLMethod> labels;
						// this condition avoids redundant valid test cases
						if(currentTransition.get(0).equals(edge))
							labels = edge.getLabel();
						else
							labels = edge.getLabel().subList(1, numberOfLabels);
						for(CrySLMethod method : labels) {
							selectedMethod = method;
							TestMethod testMethod = testClass.addTestMethod(true);
							CacheManager.instancesCache.clear();
							generateTest(curRule, testClass, currentTransition, testMethod, true);
						}
					}
				}
			}
		}
	}

	public void generateTest(CrySLRule curRule, TestClass testClass, List<TransitionEdge> currentTransition,
			TestMethod testMethod, boolean isExplicit) {
		Set<String> imports = Utils.determineImports(currentTransition);
		testClass.addImports(imports);
		
		populateMethod(curRule, currentTransition, testMethod, testClass, isExplicit);
	}

	private CrySLPredicate findEnsuringPredicate(CrySLRule curRule, List<TransitionEdge> currentTransition, boolean isExplicit) {
		List<CrySLPredicate> ensuringPredicate = Lists.newArrayList();
		
		for (CrySLPredicate pred : curRule.getPredicates()) {
			
			if(pred instanceof CrySLCondPredicate) {
				for(StateNode node : ((CrySLCondPredicate) pred).getConditionalMethods()) {
					for(TransitionEdge edge : currentTransition) {
						if(node.getName().equals(edge.getRight().getName())) {
							ensuringPredicate.add(pred);
						}
					}
				}
			}
			
			CrySLObject predParam = (CrySLObject) pred.getParameters().get(0);
			String predParamType = predParam.getJavaType();
			
			currentTransition.stream().forEach(transition -> {
				boolean match1 = FSMHandler.selectMethodBasedOnStrategy(transition, isExplicit).getParameters().stream().anyMatch(param -> {
					return param.getKey().equals(predParam.getName()) && (Utils.isSubType(param.getValue(), predParamType) || Utils.isSubType(predParamType, param.getValue()));
				});
				
				Entry<String, String> returnObj = FSMHandler.selectMethodBasedOnStrategy(transition, isExplicit).getRetObject();
				String returnObjType = returnObj.getValue().replaceAll("[\\[\\]]","");
				boolean match2 = returnObj.getKey().equals(predParam.getName()) && (Utils.isSubType(returnObjType, predParamType) || Utils.isSubType(predParamType, returnObjType));
			
				if (match1 || match2) {
					ensuringPredicate.add(pred);
				}
			});
		}
		
		if(!ensuringPredicate.isEmpty())
			return ensuringPredicate.get(ensuringPredicate.size() - 1);
		else
		{
			for (CrySLPredicate reqPred : curRule.getPredicates()) {
				Optional<ICrySLPredicateParameter> o = reqPred.getParameters().stream()
						.filter(e -> {
							return Utils.isSubType(((CrySLObject) e).getJavaType(), curRule.getClassName());
						}).findFirst();
				if (o.isPresent()) {
					return reqPred;

				}
			}
		}
		return null;
	}
	
	private void populateMethod(CrySLRule curRule, List<TransitionEdge> currentTransition, TestMethod testMethod, TestClass testClass, boolean isExplicit) {

//		if(toBeEnsuredPred == null)
//			determineEnsurePreds(curRule);
		CacheManager.toBeEnsuredPred = new SimpleEntry(findEnsuringPredicate(curRule, currentTransition, isExplicit), new SimpleEntry(curRule, null));
		List<String> methodInvocations = generateMethodInvocations(curRule, testMethod, testClass, currentTransition, isExplicit);
		if (methodInvocations.isEmpty()) {
			return;
		}
		
		for (String methodInvocation : methodInvocations) {
			testMethod.addStatementToBody(methodInvocation);
		}
		
		TestOracle testOracle = new TestOracle(curRule, testMethod);
		testOracle.generateAssertions();

//				if (codeGenerator.getToBeEnsuredPred() != null && toBeEnsured.isPresent() && !toBeEnsured.get().getKey().getParameters().get(0)
//						.equals(codeGenerator.getToBeEnsuredPred().getKey().getParameters().get(0))) {
//					Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> originalPred = toBeEnsured.get();
//					int indexOf = codeGenerator.getPredicateConnections().indexOf(originalPred);
//					codeGenerator.getPredicateConnections().remove(indexOf);
//					codeGenerator.getPredicateConnections().add(indexOf, codeGenerator.getToBeEnsuredPred());
//				}

//				reliablePreds.put(curRule.getClassName(), curRule.getPredicates());
	}

	private List<String> generateMethodInvocations(CrySLRule rule, TestMethod testMethod, TestClass testClass, List<TransitionEdge> currentTransition, boolean isExplicit) {
		Set<StateNode> killStatements = CrySLUtils.extractKillStatements(rule);
		List<String> methodInvocations = Lists.newArrayList();
		List<String> localKillers = Lists.newArrayList();
		boolean ensures = false;
		boolean complete = FSMHandler.isTransitionsComplete(rule, currentTransition);

		Set<Entry<String, String>> testMethodVariables = Sets.newHashSet();

		for (TransitionEdge edge : currentTransition) {

			Entry<CrySLMethod, Boolean> entry = FSMHandler.fetchEnsuringMethod(edge, ensures, isExplicit);
			CrySLMethod method = entry.getKey();
			ensures = entry.getValue() && complete;

			String methodName = method.getMethodName();
			// NOTE stripping away the package and retaining only method name
			methodName = methodName.substring(methodName.lastIndexOf(".") + 1);

			StringBuilder sourceLineGenerator = constructMethodCall(method);

			try {
				Set<String> exceptions = Utils.determineThrownExceptions(method);
				testMethod.addExceptions(exceptions);
				testClass.addImports(exceptions);
			} catch (final SecurityException | ClassNotFoundException e) {
				Activator.getDefault().logError(e);
			}

			Entry<String, List<Entry<String, String>>> methodInvocationWithTestMethodVariables = generateMethodInvocation(testMethod, testClass, method, rule, sourceLineGenerator);
			
			testMethodVariables.addAll(methodInvocationWithTestMethodVariables.getValue());
			String methodInvocation = methodInvocationWithTestMethodVariables.getKey();

			if (!methodInvocation.isEmpty()) {
				if (killStatements.contains(edge.to())) {
					localKillers.add(methodInvocation);
				} else 
				{
					methodInvocations.add(methodInvocation);
				}
			}
		}

		CacheManager.ensuredValues = null;
		if(CacheManager.toBeEnsuredPred.getKey() != null) {
			CacheManager.ensuredValues = new SimpleEntry<>(CacheManager.toBeEnsuredPred.getKey(), ensures);
		}

		CacheManager.kills.put(rule, localKillers);
		testMethod.addVariablesToBody(testMethodVariables);
		return methodInvocations;
	}
	
	
//	public String getLastInvokedMethodName(List<TransitionEdge> transitions) {
//		String lastInvokedMethodName = getLastInvokedMethod(transitions).toString();
//		lastInvokedMethodName = lastInvokedMethodName.substring(0, lastInvokedMethodName.lastIndexOf("("));
//
//		if (lastInvokedMethodName.contains("=")) {
//			lastInvokedMethodName = lastInvokedMethodName.substring(lastInvokedMethodName.lastIndexOf("=") + 1);
//			lastInvokedMethodName = lastInvokedMethodName.trim();
//		}
//		return lastInvokedMethodName;
//	}
//	
//	private CrySLMethod getLastInvokedMethod(List<TransitionEdge> transitions) {
//		TransitionEdge lastTransition = transitions.get(transitions.size() - 1);
//		CrySLMethod lastInvokedMethod = lastTransition.getLabel().get(0);
//		return lastInvokedMethod;
//	}
	
	
	public StringBuilder constructMethodCall(CrySLMethod method) {
		List<Entry<String, String>> parameters = method.getParameters();
		Iterator<Entry<String, String>> parametersIterator = parameters.iterator();
		StringBuilder sourceLineGenerator = new StringBuilder(method.getShortMethodName());
		sourceLineGenerator.append("(");

		do {
			if (parametersIterator.hasNext()) {
				sourceLineGenerator.append(parametersIterator.next().getKey());
			}

			if (parametersIterator.hasNext()) {
				sourceLineGenerator.append(", ");
			}

		} while (parametersIterator.hasNext());

		sourceLineGenerator.append(");");
		return sourceLineGenerator;
	}
	
	private Entry<String, List<Entry<String, String>>> generateMethodInvocation(TestMethod testMethod,
			TestClass testClass, CrySLMethod method, CrySLRule rule, StringBuilder currentInvokedMethod) {

		String methodInvocation = "";

		String className = rule.getClassName();
		String simpleClassName = Utils.retrieveOnlyClassName(className);

		// 1. Constructor method calls
		// 2. Static method calls
		// 3. Instance method calls

		// 1. Constructor method call
		// NOTE2 className is used because its later used by isSubType for resolving parameters based on the variables generated by TestGenerator
		if (currentInvokedMethod.substring(0, currentInvokedMethod.indexOf("(")).equals(simpleClassName)) {
			methodInvocation = className + " " + composeInstanceName(simpleClassName) + " = new " + currentInvokedMethod;
		}
		// 2. Static method call
		else if (currentInvokedMethod.toString().contains("getInstance")) {
			currentInvokedMethod = new StringBuilder(currentInvokedMethod.substring(currentInvokedMethod.lastIndexOf("=") + 1).trim());
			methodInvocation = className + " " + composeInstanceName(simpleClassName) + " = " + simpleClassName + "." + currentInvokedMethod;
		}
		// 3. Instance method call
		else {
			String instanceName = retrieveInstanceName();
			// Does method have a return value?
			if (method.getRetObject() != null) {
				String returnValueName = method.getRetObject().getKey();
				String returnValueType = method.getRetObject().getValue();
				
				if (!returnValueType.equals("void")) {
					String simpleType = Utils.retrieveOnlyClassName(returnValueType);
					if (Character.isUpperCase(simpleType.charAt(0))) {
						returnValueName = Character.toLowerCase(simpleType.charAt(0)) + simpleType.substring(1).replaceAll("[\\[\\]]","");
						methodInvocation = returnValueType + " " + returnValueName + " = " + instanceName + "." + currentInvokedMethod;
					} else {
						methodInvocation = returnValueType + " " + returnValueName + " = " + instanceName + "." + currentInvokedMethod;
					}
					if(CacheManager.toBeEnsuredPred.getKey().getParameters().get(0).getName().equals(method.getRetObject().getKey())) {
						updateToBeEnsured( new SimpleEntry<String, String>(returnValueName, returnValueType));
					}
				} else {
					methodInvocation = instanceName + "." + currentInvokedMethod;
				}
			}
			else {
				methodInvocation = instanceName + "." + currentInvokedMethod;
			}
		}
		return new ParameterResolver(predicatesHandler, this).replaceParameterByValue(rule, testMethod, testClass, methodInvocation, method);
	}

	static String retrieveInstanceName() {
		return CacheManager.instancesCache.peek();
	}

	private String composeInstanceName(String simpleClassName) {
		int suffix = 0;
		String prefixName = Character.toLowerCase(simpleClassName.charAt(0)) + simpleClassName.substring(1);
		String name = prefixName + suffix;
		while(CacheManager.instancesCache.contains(name)) {
			suffix++;
			name = prefixName + suffix;
		}
		CacheManager.instancesCache.push(name);
		return name;
	}

	public void updateToBeEnsured(Entry<String, String> entry) {
		if (CacheManager.toBeEnsuredPred != null) {
			CrySLPredicate existing = CacheManager.toBeEnsuredPred.getKey();
			CrySLObject predicatePar = (CrySLObject) existing.getParameters().get(0);

			if (!"this".equals(predicatePar.getVarName())) {
				List<ICrySLPredicateParameter> parameters = Lists.newArrayList();
				for (ICrySLPredicateParameter obj : existing.getParameters()) {
					CrySLObject par = ((CrySLObject) obj);
					if (Utils.isSubType(par.getJavaType(), predicatePar.getJavaType()) || Utils.isSubType(predicatePar.getJavaType(), par.getJavaType())) {
						parameters.add(new CrySLObject(entry.getKey(), par.getJavaType(), par.getSplitter()));
					}
				}
				if (!parameters.isEmpty()) {
					CacheManager.toBeEnsuredPred = new SimpleEntry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>(new CrySLPredicate(existing.getBaseObject(), existing
						.getPredName(), parameters, existing.isNegated(), existing.getConstraint()), CacheManager.toBeEnsuredPred.getValue());
				}
			}

		}
	}
	
//	public Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> determineEnsurePreds(CrySLRule rule) {
//		Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> toBeEnsured;
//		Stream<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> filter = predicateConnections.stream().filter(e -> {
//			String ruleClassName = rule.getClassName();
//			String keyClassName = e.getValue().getKey().getClassName();
//			return Utils.isSubType(ruleClassName, keyClassName) || Utils.isSubType(keyClassName, ruleClassName);
//		});
//		toBeEnsured = filter.findFirst();
//		if (toBeEnsured.isPresent()) {
//			toBeEnsuredPred = toBeEnsured.get();
//		}
//		return toBeEnsured;
//	}
}