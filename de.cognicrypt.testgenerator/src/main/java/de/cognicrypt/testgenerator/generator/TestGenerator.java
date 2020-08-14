package de.cognicrypt.testgenerator.generator;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.eclipse.core.runtime.CoreException;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

import crypto.interfaces.ICrySLPredicateParameter;
import crypto.interfaces.ISLConstraint;
import crypto.rules.CrySLComparisonConstraint;
import crypto.rules.CrySLConstraint;
import crypto.rules.CrySLConstraint.LogOps;
import crypto.rules.CrySLMethod;
import crypto.rules.CrySLObject;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.CrySLValueConstraint;
import crypto.rules.StateMachineGraph;
import crypto.rules.TransitionEdge;
import de.cognicrypt.codegenerator.generator.RuleDependencyTree;
import de.cognicrypt.codegenerator.generator.StateMachineGraphAnalyser;
import de.cognicrypt.testgenerator.Activator;
import de.cognicrypt.testgenerator.test.TestClass;
import de.cognicrypt.testgenerator.test.TestMethod;
import de.cognicrypt.testgenerator.test.TestProject;
import de.cognicrypt.testgenerator.utils.TestConstants;
import de.cognicrypt.testgenerator.utils.Utils;
import de.cognicrypt.utils.CrySLUtils;

public class TestGenerator {

	private static final Logger LOGGER = Logger.getLogger(TestGenerator.class.getName());
	
	private TestProject testProject;
	private List<CrySLRule> rules;
	private RuleDependencyTree rdt;
	private String genFolder;
	
	private List<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> predicateConnections = Lists.newArrayList();
	CrySLPredicate toBeEnsuredPred = null;
	private static HashMap<String, String> parameterCache = new HashMap<String, String>();
	private static HashMap<String, String> ruleParameterCache = new HashMap<String, String>();
	
	private static TestGenerator instance;

	private TestGenerator() {
		LOGGER.setLevel(Level.INFO);
		this.testProject = new TestProject(TestConstants.PROJECT_NAME);
		this.genFolder = this.testProject.getProjectPath() + TestConstants.innerFileSeparator + this.testProject.getSourcePath() + TestConstants.innerFileSeparator + "jca" + TestConstants.innerFileSeparator;
		LOGGER.info("Reading ruleset.");
		this.rules = CrySLUtils.readCrySLRules();
		LOGGER.info("Finished reading ruleset.");
		this.rdt = new RuleDependencyTree(rules);
	}

	public static TestGenerator getInstance() {
		if (TestGenerator.instance == null) {
			TestGenerator.instance = new TestGenerator();
		}
		return TestGenerator.instance;
	}

	public void generateTests() {
		
		List<String> selectedRules = Utils.getSelectedRules(); 
		Set<TestClass> testClasses = Sets.newHashSet();
		
		for (CrySLRule curRule : rules) {
//			if(curRule.getClassName().equals("javax.crypto.KeyGenerator")) {
			if(selectedRules.contains(curRule.getClassName())) {
				LOGGER.info("Creating tests for " + curRule.getClassName());
				String className = Utils.retrieveOnlyClassName(curRule.getClassName());
				
				TestClass testClass = new TestClass(className);
				testClass.setPackageName("jca");
				testClass.setModifier("public");
				testClasses.add(testClass);
				
				Map<String, List<CrySLPredicate>> reliablePreds = Maps.newHashMap();
				populatePredicateConnections();
//				printPredicateConnections();

				ruleParameterCache.clear();
				// valid test cases
				generateValidTests(curRule, testClass);
				
				// invalid test cases
				generateInvalidTests(curRule, testClass);
			}
		}
		writeToDisk(testClasses);
		cleanProject();
	}

	private void populatePredicateConnections() {
		for (int i = 0; i < rules.size(); i++) {
			CrySLRule cRule = rules.get(i);
			for(int j = 0; j < rules.size(); j++) {
				if(j == i)
					continue;
				
				CrySLRule nRule = rules.get(j);
				if (rdt.hasDirectPath(cRule, nRule)) {
					populatePredicateConnections(cRule, nRule);
				}
			}
		}
	}
	
	private void populatePredicateConnections(CrySLRule curRule, CrySLRule nextRule) {
		boolean isAdded = false;
		for (CrySLPredicate ensPred : curRule.getPredicates()) {
			String nextType = nextRule.getClassName();
			String predType = ((CrySLObject) ensPred.getParameters().get(0)).getJavaType();
			if (Utils.isSubType(nextType, predType) || Utils.isSubType(predType, nextType)) {
				predicateConnections.add(new SimpleEntry<>(ensPred, new SimpleEntry<CrySLRule, CrySLRule>(curRule, nextRule)));
				isAdded = true;
			}
			for (CrySLPredicate reqPred : nextRule.getRequiredPredicates()) {
				if (reqPred.equals(ensPred) && Utils.isSubType(((CrySLObject) reqPred.getParameters().get(0)).getJavaType(), predType)) {
					Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> matchedPred = predicateConnections.stream()
						.filter(e -> e.getKey().equals(ensPred)).findFirst();
					if (isAdded && matchedPred.isPresent()) {
						int newParNumber = getParameterNumber(curRule, (CrySLObject) ensPred.getParameters().get(0));
						Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> entry = matchedPred.get();
						int oldParNumber = getParameterNumber(curRule, (CrySLObject) entry.getKey().getParameters().get(0));
						if (newParNumber < oldParNumber) {
							predicateConnections.remove(entry);
							predicateConnections.add(new SimpleEntry<>(ensPred, new SimpleEntry<CrySLRule, CrySLRule>(curRule, nextRule)));
						}
					} else {
						predicateConnections.add(new SimpleEntry<>(ensPred, new SimpleEntry<CrySLRule, CrySLRule>(curRule, nextRule)));
						isAdded = true;
					}
				}
			}
		}
	}
	
	private int getParameterNumber(CrySLRule curRule, CrySLObject par) {
		Set<TransitionEdge> transitions = new HashSet<TransitionEdge>(curRule.getUsagePattern().getAllTransitions());
		for (TransitionEdge trans : transitions) {
			for (CrySLMethod potMethod : trans.getLabel()) {
				SimpleEntry<String, String> cmpPar = new SimpleEntry<String, String>(par.getVarName(), par.getJavaType());
				if (potMethod.getParameters().parallelStream()
					.anyMatch(e -> e.getKey().equals(cmpPar.getKey()) && (e.getValue().equals(cmpPar.getValue()) || e.getValue().equals(cmpPar.getValue() + "[]")))) {
					return potMethod.getParameters().size() - 1;
				} else if (potMethod.getRetObject().getKey().equals(
					cmpPar.getKey()) && (potMethod.getRetObject().getValue().equals(cmpPar.getValue()) || potMethod.getRetObject().getValue().equals(cmpPar.getValue() + "[]"))) {
					return potMethod.getParameters().size();
				}

			}
		}
		return Integer.MAX_VALUE;
	}

	private void writeToDisk(Set<TestClass> testClasses) {
		CodeHandler codeHandler = new CodeHandler(testClasses);
		try {
			codeHandler.writeToDisk(genFolder);
		} catch (Exception e) {
			Activator.getDefault().logError(e, "Failed to write to disk.");
		}
	}

	private void cleanProject() {
		LOGGER.info("Cleaning up generated project.");
		try {
			this.testProject.cleanUpProject();
		} catch (CoreException e) {
			Activator.getDefault().logError(e, "Failed to clean up.");
		}
		LOGGER.info("Finished clean up.");
	}

	private void generateInvalidTests(CrySLRule curRule, TestClass testClass) {
		Iterator<List<TransitionEdge>> invalidTransitions = getInvalidTransitionsFromStateMachine(curRule.getUsagePattern());
		while(invalidTransitions.hasNext()) {
			List<TransitionEdge> currentTransition = invalidTransitions.next();
			TestMethod testMethod = testClass.addTestMethod(false);
			
			generateValidTest(curRule, testClass, currentTransition, testMethod);
		}
	}

	private void generateValidTests(CrySLRule curRule, TestClass testClass) {
		Iterator<List<TransitionEdge>> validTransitions = getValidTransitionsFromStateMachine(curRule.getUsagePattern());
		while(validTransitions.hasNext()) {
			List<TransitionEdge> currentTransition = validTransitions.next();
			TestMethod testMethod = testClass.addTestMethod(true);

			generateValidTest(curRule, testClass, currentTransition, testMethod);
		}
	}

	private void generateValidTest(CrySLRule curRule, TestClass testClass, List<TransitionEdge> currentTransition,
			TestMethod testMethod) {
		Set<String> imports = Utils.determineImports(currentTransition);
		testClass.addImports(imports);
		
		populateMethod(curRule, currentTransition, testMethod, testClass);
	}

	private CrySLPredicate findEnsuringPredicate(CrySLRule curRule, List<TransitionEdge> currentTransition) {
		List<CrySLPredicate> ensuringPredicate = Lists.newArrayList();
		
		for (CrySLPredicate pred : curRule.getPredicates()) {
			CrySLObject predParam = (CrySLObject) pred.getParameters().get(0);
			String predParamType = predParam.getJavaType();
			
			currentTransition.stream().forEach(transition -> {
				boolean match1 = transition.getLabel().get(0).getParameters().stream().anyMatch(param -> {
					return param.getKey().equals(predParam.getName()) && (Utils.isSubType(param.getValue(), predParamType) || Utils.isSubType(predParamType, param.getValue()));
				});
				
				Entry<String, String> returnObj = transition.getLabel().get(0).getRetObject();
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

	private Iterator<List<TransitionEdge>> getValidTransitionsFromStateMachine(StateMachineGraph stateMachine) {
		StateMachineGraphAnalyser stateMachineGraphAnalyser = new StateMachineGraphAnalyser(stateMachine);
		try {
			List<List<TransitionEdge>> validTransitionsList = stateMachineGraphAnalyser.getTransitions();
			validTransitionsList.sort(new Comparator<List<TransitionEdge>>() {

				@Override
				public int compare(List<TransitionEdge> element1, List<TransitionEdge> element2) {
					return Integer.compare(element1.size(), element2.size());
				}
			});
			return validTransitionsList.iterator();
		} catch (Exception e) {
			Activator.getDefault().logError(e);
		}
		return null;
	}
	
	private List<TransitionEdge> getValidTransitionFromStateMachine(StateMachineGraph stateMachine) {
		StateMachineGraphAnalyser stateMachineGraphAnalyser = new StateMachineGraphAnalyser(stateMachine);
		try {
			List<List<TransitionEdge>> validTransitionsList = stateMachineGraphAnalyser.getTransitions();
			return validTransitionsList.get(0);
		} catch (Exception e) {
			Activator.getDefault().logError(e);
		}
		return null;
	}

	private Iterator<List<TransitionEdge>> getInvalidTransitionsFromStateMachine(StateMachineGraph stateMachine) {
		StateMachineGraphAnalyser stateMachineGraphAnalyser = new StateMachineGraphAnalyser(stateMachine);
		try {
			List<List<TransitionEdge>> invalidTransitionsList = composeInvalidTransitions(stateMachineGraphAnalyser.getTransitions());
			invalidTransitionsList.sort(new Comparator<List<TransitionEdge>>() {

				@Override
				public int compare(List<TransitionEdge> element1, List<TransitionEdge> element2) {
					return Integer.compare(element1.size(), element2.size());
				}
			});
			return invalidTransitionsList.iterator();
		} catch (final Exception e) {
			Activator.getDefault().logError(e);
		}
		return null;
	}

	private List<List<TransitionEdge>> composeInvalidTransitions(List<List<TransitionEdge>> transitionsList) {
		LinkedHashSet<List<TransitionEdge>> resultantList = Sets.newLinkedHashSet();
		
		// case 1 : transitions without accepting state => IncompleteOperationError
		for (List<TransitionEdge> transition : transitionsList) {
			List<TransitionEdge> result = transition.stream().filter(e -> e.getRight().getAccepting() != true).collect(Collectors.toList());
			if(!result.isEmpty())
				resultantList.add(result);
		}
		
		// case 2 : transitions with missing intermediate states => TypestateError
		for (List<TransitionEdge> transition : transitionsList) {
			if(transition.size() == 1)
				break;
			
			Iterator<TransitionEdge> itr = transition.iterator();
			while (itr.hasNext()) {
				TransitionEdge edge = itr.next();
				if (edge.getLeft().isInitialState())
					continue;
			
				if(edge.getRight().getAccepting()) {
					continue;
				}
				
				itr.remove();
				resultantList.add(transition);
				break;
			}
		}
		
		return Lists.newArrayList(resultantList);
	}

	private void generateAssertions(CrySLRule rule, TestMethod testMethod) {
		generatePredicateAssertions(rule, testMethod);
		generateStateAssertions(rule, testMethod);
	}

	private void generateStateAssertions(CrySLRule rule, TestMethod testMethod) {
		String simpleClassName = Utils.retrieveOnlyClassName(rule.getClassName());
		String instanceName = Character.toLowerCase(simpleClassName.charAt(0)) + simpleClassName.substring(1);

		if (testMethod.isValid()) {
			testMethod.addStatementToBody("Assertions.mustBeInAcceptingState(" + instanceName + ");");
		} else {
			testMethod.addStatementToBody("Assertions.mustNotBeInAcceptingState(" + instanceName + ");");
		}
	}

	private void generatePredicateAssertions(CrySLRule rule, TestMethod testMethod) {
		CrySLPredicate predicate = this.toBeEnsuredPred;
		
		if(predicate != null) {
			String param = predicate.getParameters().get(0).getName();
			String simpleClassName = Utils.retrieveOnlyClassName(rule.getClassName());
			String instanceName = Character.toLowerCase(simpleClassName.charAt(0)) + simpleClassName.substring(1);
			
			if (testMethod.isValid()) {
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

//	private void printPredicateConnections() {
//		for (Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> c : this.predicateConnections) {
//			CrySLPredicate key = c.getKey();
//			Entry<CrySLRule, CrySLRule> value = c.getValue();
//			System.out.println(key + " : " + Utils.retrieveOnlyClassName(value.getKey().getClassName()) + " -> " + Utils.retrieveOnlyClassName(value.getValue().getClassName()));
//		}
//	}
	
	private void populateMethod(CrySLRule curRule, List<TransitionEdge> currentTransition, TestMethod testMethod, TestClass testClass) {

		this.toBeEnsuredPred = findEnsuringPredicate(curRule, currentTransition);
		generateMethodInvocations(curRule, testMethod, testClass, currentTransition);
		generateAssertions(curRule, testMethod);

//				if (this.codeGenerator.getToBeEnsuredPred() != null && toBeEnsured.isPresent() && !toBeEnsured.get().getKey().getParameters().get(0)
//						.equals(this.codeGenerator.getToBeEnsuredPred().getKey().getParameters().get(0))) {
//					Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> originalPred = toBeEnsured.get();
//					int indexOf = this.codeGenerator.getPredicateConnections().indexOf(originalPred);
//					this.codeGenerator.getPredicateConnections().remove(indexOf);
//					this.codeGenerator.getPredicateConnections().add(indexOf, this.codeGenerator.getToBeEnsuredPred());
//				}

//				reliablePreds.put(curRule.getClassName(), curRule.getPredicates());
	}

	private void generateMethodInvocations(CrySLRule rule, TestMethod testMethod, TestClass testClass, List<TransitionEdge> currentTransitions) {
//		Set<StateNode> killStatements = this.codeGenerator.extractKillStatements(rule);
		List<String> methodInvocations = Lists.newArrayList();
//		List<String> localKillers = Lists.newArrayList();
//		boolean ensures = false;

		Set<Entry<String, String>> testMethodVariables = Sets.newHashSet();
//		Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> pre = new SimpleEntry<>(this.codeGenerator.getToBeEnsuredPred().getKey(), this.codeGenerator.getToBeEnsuredPred().getValue());

		StringBuilder instanceName = new StringBuilder();
		for (TransitionEdge transition : currentTransitions) {
			List<CrySLMethod> labels = transition.getLabel();
//			Entry<CrySLMethod, Boolean> entry = this.codeGenerator.fetchEnsuringMethod(usablePreds, pre, labels, ensures);
			CrySLMethod method = labels.get(0);
//			ensures = entry.getValue();
//			String methodName = method.getMethodName();
//			// NOTE stripping away the package and retaining only method name
//			methodName = methodName.substring(methodName.lastIndexOf(".") + 1);

			StringBuilder sourceLineGenerator = constructMethodCall(method);

			try {
				Set<String> exceptions = determineThrownExceptions(method);
				testMethod.addExceptions(exceptions);
				testClass.addImports(exceptions);
			} catch (final SecurityException | ClassNotFoundException e) {
				Activator.getDefault().logError(e);
			}

			Entry<String, List<Entry<String, String>>> methodInvocationWithTestMethodVariables = generateMethodInvocation(testMethod, testClass, method, rule, sourceLineGenerator, instanceName);
			
			testMethodVariables.addAll(methodInvocationWithTestMethodVariables.getValue());
			String methodInvocation = methodInvocationWithTestMethodVariables.getKey();

			if (!methodInvocation.isEmpty()) {
//				if (killStatements.contains(transition.to())) {
//					localKillers.add(methodInvocation);
//				} else 
				{
					methodInvocations.add(methodInvocation);
				}
			}
		}
		
		testMethod.addVariablesToBody(testMethodVariables);
		for (String methodInvocation : methodInvocations) {
			testMethod.addStatementToBody(methodInvocation);
		}
	}
	
	public String getLastInvokedMethodName(List<TransitionEdge> transitions) {
		String lastInvokedMethodName = getLastInvokedMethod(transitions).toString();
		lastInvokedMethodName = lastInvokedMethodName.substring(0, lastInvokedMethodName.lastIndexOf("("));

		if (lastInvokedMethodName.contains("=")) {
			lastInvokedMethodName = lastInvokedMethodName.substring(lastInvokedMethodName.lastIndexOf("=") + 1);
			lastInvokedMethodName = lastInvokedMethodName.trim();
		}
		return lastInvokedMethodName;
	}
	
	private CrySLMethod getLastInvokedMethod(List<TransitionEdge> transitions) {
		TransitionEdge lastTransition = transitions.get(transitions.size() - 1);
		CrySLMethod lastInvokedMethod = lastTransition.getLabel().get(0);
		return lastInvokedMethod;
	}
	
	
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
	
	public Set<String> determineThrownExceptions(CrySLMethod method) throws SecurityException, ClassNotFoundException {
		Set<Class<?>> exceptionClasses = Sets.newHashSet();
		Set<String> exceptions = Sets.newHashSet();
		Class<?>[] methodParameters = Utils.collectParameterTypes(method.getParameters());
		String className = method.getMethodName().substring(0, method.getMethodName().lastIndexOf("."));
		Method[] methods = Class.forName(className).getMethods();
		String methodName = method.getShortMethodName();
		for (Method meth : methods) {
			if (meth.getExceptionTypes().length > 0 && meth.getName().equals(methodName) && methodParameters.length == meth.getParameterCount()) {
				if (matchMethodParameters(methodParameters, meth.getParameterTypes())) {
					exceptionClasses.addAll(Arrays.asList(meth.getExceptionTypes()));
				}
			}
		}
		
		Constructor[] constructors = Class.forName(className).getConstructors();
		for (Constructor cons: constructors) {
			String fullyQualifiedName = cons.getName();
			String consName = Utils.retrieveOnlyClassName(fullyQualifiedName);
			if (cons.getExceptionTypes().length > 0 && consName.equals(methodName) && methodParameters.length == cons.getParameterCount()) {
				if (matchMethodParameters(methodParameters, cons.getParameterTypes())) {
					exceptionClasses.addAll((Collection<? extends Class<?>>) Arrays.asList(cons.getExceptionTypes()));
				}
			}
		}

		for (Class<?> exception : exceptionClasses) {
			exceptions.add(exception.getName());
		}
		return exceptions;
	}
	
	private boolean matchMethodParameters(Class<?>[] methodParameters, Class<?>[] classes) {
		for (int i = 0; i < methodParameters.length; i++) {
			if (methodParameters[i].getName().equals("AnyType")) {
				continue;
			} else if (!methodParameters[i].equals(classes[i])) {
				return false;
			}
		}
		return true;
	}

	private Entry<String, List<Entry<String, String>>> generateMethodInvocation(TestMethod testMethod,
			TestClass testClass, CrySLMethod method, CrySLRule rule, StringBuilder currentInvokedMethod, StringBuilder instanceName1) {

		String methodInvocation = "";

		String className = rule.getClassName();
		String simpleClassName = Utils.retrieveOnlyClassName(className);
		String instanceName = Character.toLowerCase(simpleClassName.charAt(0)) + simpleClassName.substring(1);

		// 1. Constructor method calls
		// 2. Static method calls
		// 3. Instance method calls

		// 1. Constructor method call
		// NOTE2 className is used because its later used by isSubType for resolving parameters based on the variables generated by TestGenerator
		if (currentInvokedMethod.substring(0, currentInvokedMethod.indexOf("(")).equals(simpleClassName)) {
			methodInvocation = className + " " + instanceName + " = new " + currentInvokedMethod;
		}
		// 2. Static method call
		else if (currentInvokedMethod.toString().contains("getInstance")) {
			currentInvokedMethod = new StringBuilder(currentInvokedMethod.substring(currentInvokedMethod.lastIndexOf("=") + 1).trim());
			methodInvocation = className + " " + instanceName + " = " + simpleClassName + "." + currentInvokedMethod;
		}
		// 3. Instance method call
		else {
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
					if(this.toBeEnsuredPred.getParameters().get(0).getName().equals(method.getRetObject().getKey())) {
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
		return replaceParameterByValue(rule, testMethod, testClass, methodInvocation, method);
	}

	private Entry<String, List<Entry<String, String>>> replaceParameterByValue(CrySLRule rule,
			TestMethod testMethod, TestClass testClass, String currentInvokedMethod, CrySLMethod crySLMethod) {

		String methodNamdResultAssignment = currentInvokedMethod.substring(0, currentInvokedMethod.indexOf("("));
		String methodParameter = currentInvokedMethod.substring(currentInvokedMethod.indexOf("("), currentInvokedMethod.indexOf(")"));
		String appendix = currentInvokedMethod.substring(currentInvokedMethod.indexOf(")"), currentInvokedMethod.length());
		List<Entry<String, String>> variablesToBeAdded = Lists.newArrayList();
		List<Entry<String, String>> declaredVariables = testMethod.getDeclaredVariables();
		List<Entry<String, String>> parametersOfCall = crySLMethod.getParameters();
		
		for (Entry<String, String> parameter : parametersOfCall) {

			// STEP 1 : check if any of the declared variables match the parameter
			Optional<Entry<String, String>> typeMatch = declaredVariables.stream()
				.filter(e -> (Utils.isSubType(e.getValue(), parameter.getValue()) || Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
			if (typeMatch.isPresent()) {
				updateToBeEnsured(typeMatch.get());
				methodParameter = methodParameter.replace(parameter.getKey(), typeMatch.get().getKey());
				continue;
			}
			
			// STEP 2 : check if parameter can be ensured by any of the predicate connections
			Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> producer = this.predicateConnections.stream()
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
				final CrySLRule producerRule = (CrySLRule) producer.get().getValue().getKey();
				if(!testMethod.isValid()) {
					// even for invalid tests the method invocations are generated correctly for implicit rules
					testMethod.setValid(true);
					generateValidTest(producerRule, testClass, getValidTransitionFromStateMachine(producerRule.getUsagePattern()), testMethod);
					testMethod.setValid(false);
				} else {
					generateValidTest(producerRule, testClass, getValidTransitionFromStateMachine(producerRule.getUsagePattern()), testMethod);
				}
				
				Optional<Entry<String, String>> match = declaredVariables.stream()
						.filter(e -> (Utils.isSubType(e.getValue(), parameter.getValue()) || Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
				if (match.isPresent()) {
					updateToBeEnsured(match.get());
					methodParameter = methodParameter.replace(parameter.getKey(), match.get().getKey());
				}
				continue;
			}
			
			// STEP 3 : check if parameter can be generated by analysing CONSTRAINTS of the corresponding CrySL rule
			String name = analyseConstraints(parameter, rule, testClass, methodNamdResultAssignment.substring(methodNamdResultAssignment.lastIndexOf(".") + 1));
			if (!name.isEmpty()) {
				// NOTE2 what if a method has two parameter both of which can be resolved from using CONSTRAINTS, then in that case wouldn't methodParameter overwritten?
				methodParameter = methodParameter.replace(parameter.getKey(), name);
				continue;
			}

			// STEP 4 : If everything fails, then it add the parameter as declared variables in the test method
			variablesToBeAdded.add(parameter);
			String paramType = parameter.getValue();
			if (paramType.contains(".")) {
				testClass.addImport(parameter.getValue());
			}	

		}
		
		currentInvokedMethod = methodNamdResultAssignment + methodParameter + appendix;
		return new SimpleEntry<>(currentInvokedMethod, variablesToBeAdded);
	}
	
	public void updateToBeEnsured(Entry<String, String> entry) {
		if (toBeEnsuredPred != null) {
			CrySLPredicate existing = toBeEnsuredPred;
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
					toBeEnsuredPred = new CrySLPredicate(existing.getBaseObject(), existing
						.getPredName(), parameters, existing.isNegated(), existing.getConstraint());
				}
			}

		}
	}
	
	public String analyseConstraints(Entry<String, String> parameter, CrySLRule rule, TestClass testClass, String methodName) {
		List<ISLConstraint> constraints = rule.getConstraints().stream().filter(e -> e.getInvolvedVarNames().contains(parameter.getKey())).collect(Collectors.toList());

		for (ISLConstraint constraint : constraints) {
			// handle CrySLValueConstraint
			String name = resolveCrySLConstraint(rule, parameter, constraint, methodName);
			if (!name.isEmpty()) {
				if ("java.lang.String".equals(parameter.getValue())) {
					name = "\"" + name + "\"";
				} else if ("java.lang.String[]".equals(parameter.getValue())) {
					name = "new String[]{\"" + name + "\"}";
				} else if ("java.math.BigInteger".equals(parameter.getValue())) {
					name = "BigInteger.valueOf(" + name + ")";
					testClass.addImport("java.math.BigInteger");
				} else {
					ruleParameterCache.putIfAbsent(parameter.getKey(), name);
				}
				return name;
			}
		}
		return "";
	}
	
	private String resolveCrySLConstraint(CrySLRule rule, Entry<String, String> parameter, ISLConstraint constraint, String methodName) {
		return resolveCrySLConstraint(rule, parameter, constraint, methodName, false);
	}
	
	private String resolveCrySLConstraint(CrySLRule rule, Entry<String, String> parameter, ISLConstraint constraint, String methodName, boolean onlyEval) {
		String parVarName = parameter.getKey();
		if (constraint instanceof CrySLValueConstraint) {
			CrySLValueConstraint asVC = (CrySLValueConstraint) constraint;
			String constraintValue = asVC.getValueRange().get(0);
			if (onlyEval) {
				if (ruleParameterCache.containsKey(parVarName) && asVC.getValueRange().contains(ruleParameterCache.get(parVarName))) {
					return constraintValue;
				}
			} else if (asVC.getInvolvedVarNames().contains(parVarName)) {
				if ("transformation".equals(parVarName) && Arrays.asList(new String[] { "AES" }).contains(constraintValue)) {
					constraintValue += dealWithCipherGetInstance(rule);
				}
				ruleParameterCache.putIfAbsent(parVarName, constraintValue);
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
						value = Integer.parseInt(right.getName());
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
				TestGenerator.parameterCache.putIfAbsent(varName, secureInt);
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
						if (!resolveCrySLConstraint(rule, parameter, right, methodName, true).isEmpty()) {
							return resolveCrySLConstraint(rule, parameter, left, methodName);
						} else {
							return "";
						}
					} else {
						if (resolveCrySLConstraint(rule, parameter, left, methodName, true).isEmpty()) {
							return resolveCrySLConstraint(rule, parameter, right, methodName);
						} else {
							return resolveCrySLConstraint(rule, parameter, left, methodName);
						}
					}
				} else if (!resolveCrySLConstraint(rule, parameter, left, methodName).isEmpty()) {
					return resolveCrySLConstraint(rule, parameter, right, methodName);
				}
				return "";
			} else if (operator == LogOps.or) {
				if (!onlyEval) {
					if (left.getInvolvedVarNames().contains(parVarName)) {
						if (resolveCrySLConstraint(rule, parameter, left, methodName).isEmpty()) {
							if (right.getInvolvedVarNames().contains(parVarName) && !resolveCrySLConstraint(rule, parameter, right, methodName, true).isEmpty()) {
								return resolveCrySLConstraint(rule, parameter, right, methodName);
							} else {
								return "";
							}
						}
						return resolveCrySLConstraint(rule, parameter, left, methodName);
					}
					return resolveCrySLConstraint(rule, parameter, right, methodName);
				} else {
					String leftResult = resolveCrySLConstraint(rule, parameter, left, methodName, onlyEval);
					if (!leftResult.isEmpty()) {
						return leftResult;
					} else {
						return resolveCrySLConstraint(rule, rightAlternative, right, methodName, onlyEval);
					}
				}
			} else if (operator == LogOps.implies) {
				if (!right.getInvolvedVarNames().contains(parVarName) || resolveCrySLConstraint(rule, leftAlternative, left, methodName, true).isEmpty()) {
					return "";
				}
				return resolveCrySLConstraint(rule, parameter, right, methodName);
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