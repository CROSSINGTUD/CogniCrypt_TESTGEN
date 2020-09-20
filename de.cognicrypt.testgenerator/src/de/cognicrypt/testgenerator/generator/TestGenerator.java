package de.cognicrypt.testgenerator.generator;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.Stack;
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
import crypto.rules.CrySLCondPredicate;
import crypto.rules.CrySLConstraint;
import crypto.rules.CrySLConstraint.LogOps;
import crypto.rules.CrySLMethod;
import crypto.rules.CrySLObject;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.CrySLValueConstraint;
import crypto.rules.StateMachineGraph;
import crypto.rules.StateNode;
import crypto.rules.TransitionEdge;
import de.cognicrypt.codegenerator.generator.RuleDependencyTree;
import de.cognicrypt.testgenerator.generator.StateMachineGraphAnalyser;
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
	private RuleDependencyTree rdt;
	private String genFolder;
	
	private List<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> predicateConnections = Lists.newArrayList();
	private Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> toBeEnsuredPred = null;
	private Entry<CrySLPredicate, Boolean> ensuredValues = null;
	private static HashMap<String, String> parameterCache = Maps.newHashMap();
	private static HashMap<String, String> ruleParameterCache = Maps.newHashMap();
	private Map<CrySLRule, List<String>> kills = Maps.newHashMap();
	private Stack<String> instancesCache = new Stack<>();
	
	private static TestGenerator instance;

	private TestGenerator() {
		LOGGER.setLevel(Level.INFO);
		testProject = new TestProject(Constants.PROJECT_NAME);
		genFolder = testProject.getProjectPath() + Constants.innerFileSeparator + testProject.getSourcePath() + Constants.innerFileSeparator + "jca" + Constants.innerFileSeparator;
		LOGGER.info("Reading ruleset.");
		rules = CrySLUtils.readCrySLRules();
		LOGGER.info("Finished reading ruleset.");
		rdt = new RuleDependencyTree(rules);
		populatePredicateConnections();
//		printPredicateConnections();
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
		
		Iterator<CrySLRule> ruleIterator = rules.iterator();
		while (ruleIterator.hasNext()) {
			CrySLRule curRule = ruleIterator.next();
			if(curRule.getClassName().equals("java.security.SecureRandom")) {
//			if(selectedRules.contains(curRule.getClassName())) {
				LOGGER.info("Creating tests for " + curRule.getClassName());
				String className = Utils.retrieveOnlyClassName(curRule.getClassName());
				
				TestClass testClass = new TestClass(className);
				testClass.setPackageName("jca");
				testClass.setModifier("public");
				testClasses.add(testClass);
				
//				Map<String, List<CrySLPredicate>> reliablePreds = Maps.newHashMap();

				ruleParameterCache.clear();
				// valid test cases
				generateValidTests(curRule, testClass);
				
				// invalid test cases
				generateInvalidTests(curRule, testClass);
			}
		}
		writeToDisk(testClasses);
		cleanProject();
		LOGGER.info("Total rules covered : " + testClasses.size());
		LOGGER.info("Total test cases generated : " + calculateTotalTests(testClasses));
	}

	private int calculateTotalTests(Set<TestClass> testClasses) {
		int total = 0;
		for (TestClass testClass : testClasses) {
			total += testClass.getMethods().stream().filter(m -> m instanceof TestMethod).count();
		}
		return total;
	}

	private void populatePredicateConnections() {
		for (int i = 0; i < rules.size(); i++) {
			CrySLRule cRule = rules.get(i);
			for(int j = 0; j < rules.size(); j++) {
//				if(j == i)
//					continue;
				
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
					.filter(e -> {
						if(Utils.isSubType(e.getValue().getValue().getClassName(), nextRule.getClassName()) || Utils.isSubType(nextRule.getClassName(), e.getValue().getValue().getClassName())) {
							if(e.getKey().equals(ensPred))
								return true;
						}
						return false;
					}).findFirst();
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
			testProject.cleanUpProject();
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
			instancesCache.clear();
			generateTest(curRule, testClass, currentTransition, testMethod, true);
		}
	}

	private void generateValidTests(CrySLRule curRule, TestClass testClass) {
//		Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> toBeEnsured = determineEnsurePreds(curRule);
		Iterator<List<TransitionEdge>> validTransitions = getValidTransitionsFromStateMachine(curRule.getUsagePattern());
		while(validTransitions.hasNext()) {
			List<TransitionEdge> currentTransition = validTransitions.next();
			TestMethod testMethod = testClass.addTestMethod(true);
			instancesCache.clear();
			generateTest(curRule, testClass, currentTransition, testMethod, true);
		}
	}

	private void generateTest(CrySLRule curRule, TestClass testClass, List<TransitionEdge> currentTransition,
			TestMethod testMethod, boolean isExplicit) {
		Set<String> imports = Utils.determineImports(currentTransition);
		testClass.addImports(imports);
		
		populateMethod(curRule, currentTransition, testMethod, testClass, isExplicit);
	}

	private CrySLPredicate findEnsuringPredicate(CrySLRule curRule, List<TransitionEdge> currentTransition) {
		List<CrySLPredicate> ensuringPredicate = Lists.newArrayList();
		
		for (CrySLPredicate pred : curRule.getPredicates()) {
			CrySLObject predParam = (CrySLObject) pred.getParameters().get(0);
			String predParamType = predParam.getJavaType();
			
			if(pred instanceof CrySLCondPredicate) {
				for(StateNode node : ((CrySLCondPredicate) pred).getConditionalMethods()) {
					for(TransitionEdge edge : currentTransition) {
						if(node.getName().equals(edge.getRight().getName())) {
							ensuringPredicate.add(pred);
						}
					}
				}
			}
			
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
		try {
			return getTransitionsFromStateMachine(stateMachine);
		} catch (Exception e) {
			Activator.getDefault().logError(e);
		}
		return null;
	}

	private Iterator<List<TransitionEdge>> getTransitionsFromStateMachine(StateMachineGraph stateMachine) throws Exception {
		StateMachineGraphAnalyser stateMachineGraphAnalyser = new StateMachineGraphAnalyser(stateMachine);
		List<List<TransitionEdge>> validTransitionsList = stateMachineGraphAnalyser.getTransitions();
		validTransitionsList.sort(new Comparator<List<TransitionEdge>>() {

			@Override
			public int compare(List<TransitionEdge> element1, List<TransitionEdge> element2) {
				return Integer.compare(element1.size(), element2.size());
			}
		});
		return validTransitionsList.iterator();
	}
	
	private List<TransitionEdge> getValidTransitionFromStateMachine(StateMachineGraph stateMachine) {
		try {
			Iterator<List<TransitionEdge>> validTransitions = getTransitionsFromStateMachine(stateMachine);
			while (validTransitions.hasNext()) {
				List<TransitionEdge> currentTransitions = validTransitions.next();
				for (TransitionEdge transition : currentTransitions) {
					Entry<CrySLMethod, Boolean> entry = fetchEnsuringMethod(transition, false);
					if(entry.getValue()) {
						return currentTransitions;
					}
				}
			}
		} catch (Exception e) {
			Activator.getDefault().logError(e);
		}
		return null;
	}

	private Iterator<List<TransitionEdge>> getInvalidTransitionsFromStateMachine(StateMachineGraph stateMachine) {
		try {
			List<List<TransitionEdge>> invalidTransitionsList = composeInvalidTransitions(stateMachine);
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

	private List<List<TransitionEdge>> composeInvalidTransitions(StateMachineGraph stateMachine) throws Exception {
		StateMachineGraphAnalyser stateMachineGraphAnalyser = new StateMachineGraphAnalyser(stateMachine);
		ArrayList<List<TransitionEdge>> transitionsList = stateMachineGraphAnalyser.getTransitions();
		ArrayList<List<TransitionEdge>> resultantList = Lists.newArrayList();
		
		// case 1 : transitions without accepting state => IncompleteOperationError
		composeIncompleteOperationErrorTransitions(transitionsList, resultantList);
		
		// case 2 : transitions with missing intermediate states => TypestateError
		composeTypestateErrorTransitions(transitionsList, resultantList);
		
		return Lists.newArrayList(resultantList);
	}

	private void composeTypestateErrorTransitions(ArrayList<List<TransitionEdge>> transitionsList, List<List<TransitionEdge>> resultantList) {
		for (List<TransitionEdge> transition : transitionsList) {
			int endIndex = transition.size() - 1;
			int skipIndex = 1;
			if (endIndex > 1) {
				while (skipIndex < endIndex) {
					List<TransitionEdge> temp = Lists.newArrayList();
					ListIterator<TransitionEdge> t = transition.listIterator();
		
					while (t.hasNext()) {
						if (t.nextIndex() == skipIndex) {
							t.next();
							continue;
						}
						TransitionEdge edge = t.next();
						temp.add(edge);
					}
					if (!temp.isEmpty() && !Utils.isPresent(temp, resultantList) && !Utils.isPresent(temp, transitionsList))
						resultantList.add(new ArrayList<TransitionEdge>(temp));
					
					skipIndex++;
				}
			}
		}
	}

	private void composeIncompleteOperationErrorTransitions(ArrayList<List<TransitionEdge>> transitionsList, List<List<TransitionEdge>> resultantList) {
		for (List<TransitionEdge> transition : transitionsList) {
			List<TransitionEdge> temp = Lists.newArrayList();
			Iterator<TransitionEdge> t = transition.iterator();
			while (t.hasNext()) {
				TransitionEdge edge = t.next();
				if (edge.getRight().getAccepting())
					break;
				temp.add(edge);
				if (!temp.isEmpty() && !Utils.isPresent(temp, resultantList) && !Utils.isPresent(temp, transitionsList))
					resultantList.add(new ArrayList<TransitionEdge>(temp));
			}
		}
	}

	private void generateAssertions(CrySLRule rule, TestMethod testMethod) {
		generatePredicateAssertions(rule, testMethod);
		List<String> killStmts = kills.get(rule);	
		for (String stmt : killStmts) {
			testMethod.addStatementToBody(stmt);
		}
		generateStateAssertions(rule, testMethod);
		instancesCache.pop();
	}

	private void generateStateAssertions(CrySLRule rule, TestMethod testMethod) {
		String simpleClassName = Utils.retrieveOnlyClassName(rule.getClassName());
		String instanceName = retrieveInstanceName();

		if (testMethod.isValid()) {
			testMethod.addStatementToBody("Assertions.mustBeInAcceptingState(" + instanceName + ");");
		} else {
			testMethod.addStatementToBody("Assertions.mustNotBeInAcceptingState(" + instanceName + ");");
		}
	}

	private void generatePredicateAssertions(CrySLRule rule, TestMethod testMethod) {
		if(ensuredValues != null) {
			CrySLPredicate predicate = ensuredValues.getKey();
			String param = predicate.getParameters().get(0).getName();
			String simpleClassName = Utils.retrieveOnlyClassName(rule.getClassName());
			String instanceName = retrieveInstanceName();
			
			if (ensuredValues.getValue()) {
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
//		for (Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> c : predicateConnections) {
//			CrySLPredicate key = c.getKey();
//			Entry<CrySLRule, CrySLRule> value = c.getValue();
//			System.out.println(key + " : " + Utils.retrieveOnlyClassName(value.getKey().getClassName()) + " -> " + Utils.retrieveOnlyClassName(value.getValue().getClassName()));
//		}
//	}
	
	private void populateMethod(CrySLRule curRule, List<TransitionEdge> currentTransition, TestMethod testMethod, TestClass testClass, boolean isImplicit) {

//		if(toBeEnsuredPred == null)
//			determineEnsurePreds(curRule);
		toBeEnsuredPred = new SimpleEntry(findEnsuringPredicate(curRule, currentTransition), new SimpleEntry(curRule, null));
		List<String> methodInvocations = generateMethodInvocations(curRule, testMethod, testClass, currentTransition, isImplicit);
		if (methodInvocations.isEmpty()) {
			return;
		}
		
		for (String methodInvocation : methodInvocations) {
			testMethod.addStatementToBody(methodInvocation);
		}
		
		generateAssertions(curRule, testMethod);

//				if (codeGenerator.getToBeEnsuredPred() != null && toBeEnsured.isPresent() && !toBeEnsured.get().getKey().getParameters().get(0)
//						.equals(codeGenerator.getToBeEnsuredPred().getKey().getParameters().get(0))) {
//					Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> originalPred = toBeEnsured.get();
//					int indexOf = codeGenerator.getPredicateConnections().indexOf(originalPred);
//					codeGenerator.getPredicateConnections().remove(indexOf);
//					codeGenerator.getPredicateConnections().add(indexOf, codeGenerator.getToBeEnsuredPred());
//				}

//				reliablePreds.put(curRule.getClassName(), curRule.getPredicates());
	}

	private List<String> generateMethodInvocations(CrySLRule rule, TestMethod testMethod, TestClass testClass, List<TransitionEdge> currentTransitions, boolean isExplicit) {
		Set<StateNode> killStatements = extractKillStatements(rule);
		List<String> methodInvocations = Lists.newArrayList();
		List<String> localKillers = Lists.newArrayList();
		boolean ensures = false;
		boolean complete = isTransitionsComplete(rule, currentTransitions);

		Set<Entry<String, String>> testMethodVariables = Sets.newHashSet();

		for (TransitionEdge transition : currentTransitions) {

			Entry<CrySLMethod, Boolean> entry = fetchEnsuringMethod(transition, ensures);
			CrySLMethod method = entry.getKey();
			ensures = entry.getValue() && complete;

			String methodName = method.getMethodName();
			// NOTE stripping away the package and retaining only method name
			methodName = methodName.substring(methodName.lastIndexOf(".") + 1);

			StringBuilder sourceLineGenerator = constructMethodCall(method);

			try {
				Set<String> exceptions = determineThrownExceptions(method);
				testMethod.addExceptions(exceptions);
				testClass.addImports(exceptions);
			} catch (final SecurityException | ClassNotFoundException e) {
				Activator.getDefault().logError(e);
			}

			Entry<String, List<Entry<String, String>>> methodInvocationWithTestMethodVariables = generateMethodInvocation(testMethod, testClass, method, rule, sourceLineGenerator);
			
			testMethodVariables.addAll(methodInvocationWithTestMethodVariables.getValue());
			String methodInvocation = methodInvocationWithTestMethodVariables.getKey();

			if (!methodInvocation.isEmpty()) {
				if (killStatements.contains(transition.to())) {
					localKillers.add(methodInvocation);
				} else 
				{
					methodInvocations.add(methodInvocation);
				}
			}
		}

		ensuredValues = null;
		if(toBeEnsuredPred.getKey() != null) {
			ensuredValues = new SimpleEntry<>(toBeEnsuredPred.getKey(), ensures);
		}

		kills.put(rule, localKillers);
		testMethod.addVariablesToBody(testMethodVariables);
		return methodInvocations;
	}

	public boolean isTransitionsComplete(CrySLRule rule, List<TransitionEdge> currentTransitions) {
		if(toBeEnsuredPred.getKey() == null)
			return true;
			
		StateMachineGraphAnalyser smg = new StateMachineGraphAnalyser(rule.getUsagePattern());
		ArrayList<List<TransitionEdge>> trans = null;
		if(toBeEnsuredPred.getKey() instanceof CrySLCondPredicate) {
			Set<StateNode> nodes = ((CrySLCondPredicate) toBeEnsuredPred.getKey()).getConditionalMethods();
			trans = smg.getTransitionsUpto(nodes.iterator().next());
		}
		else {
			trans = smg.getTransitions();
		}
		for (List<TransitionEdge> t : trans) {
			int index = Collections.indexOfSubList(currentTransitions, t);
			if(index != -1)
				return true;
		}
		return false;
	}
	
	public Set<StateNode> extractKillStatements(CrySLRule rule) {
		Set<StateNode> killStatements = rule.getPredicates().stream().filter(pred -> pred.isNegated() && pred instanceof CrySLCondPredicate)
			.map(e -> ((CrySLCondPredicate) e).getConditionalMethods()).reduce(new HashSet<>(), (a, b) -> {
				a.addAll(b);
				return a;
			});
		return killStatements;
	}
	
	public Entry<CrySLMethod, Boolean> fetchEnsuringMethod(TransitionEdge transition, boolean ensures) {
		List<CrySLMethod> labels = transition.getLabel();
		
		if(toBeEnsuredPred.getKey() == null) {
			ensures = true;
			return new AbstractMap.SimpleEntry<CrySLMethod, Boolean>(labels.get(0), ensures);
		}
		
		CrySLMethod method = fetchCorrespondingMethod(transition, null);
		if (method != null) {
			ensures  = true;
		}
		else {
			method = labels.get(0);
		}
		return new AbstractMap.SimpleEntry<CrySLMethod, Boolean>(method, ensures);
	}
	
	private CrySLMethod fetchCorrespondingMethod(TransitionEdge transition, Set<CrySLObject> set) {
		
		if(toBeEnsuredPred.getKey() instanceof CrySLCondPredicate) {
			for(StateNode node : ((CrySLCondPredicate) toBeEnsuredPred.getKey()).getConditionalMethods()) {
				if(node.getName().equals(transition.getRight().getName()))
					return transition.getLabel().get(0);
			}
		}
		
		CrySLObject objectOfPred = (CrySLObject) toBeEnsuredPred.getKey().getParameters().get(0);
		String predVarType = objectOfPred.getJavaType();
		String predVarName = objectOfPred.getVarName();

		for (CrySLMethod label : transition.getLabel()) {
			//Method
			Entry<String, String> retObject = label.getRetObject();
			String returnType = retObject.getValue();
			String returnVarName = retObject.getKey();

			if (Utils.isSubType(predVarType, returnType) && returnVarName
				.equals(predVarName) || (predVarName.equals("this") && label.getMethodName().endsWith(predVarType.substring(predVarType.lastIndexOf('.') + 1)))) {
				return label;
			}
			for (Entry<String, String> par : label.getParameters()) {
				String parType = par.getValue();
				String parVarName = par.getKey();

				if ((Utils.isSubType(predVarType, parType) || Utils.isSubType(parType, predVarType)) && (parVarName.equals(predVarName) || "this".equals(predVarName))) {
					return label;
				}
			}
		}
		return null;
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
			if (methodParameters[i].getName().equals("de.cognicrypt.testgenerator.utils.AnyType")) {
				continue;
			} else if (!methodParameters[i].equals(classes[i])) {
				return false;
			}
		}
		return true;
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
					if(toBeEnsuredPred.getKey().getParameters().get(0).getName().equals(method.getRetObject().getKey())) {
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

	private String retrieveInstanceName() {
		return instancesCache.peek();
	}

	private String composeInstanceName(String simpleClassName) {
		int suffix = 0;
		String prefixName = Character.toLowerCase(simpleClassName.charAt(0)) + simpleClassName.substring(1);
		String name = prefixName + suffix;
		while(instancesCache.contains(name)) {
			suffix++;
			name = prefixName + suffix;
		}
		instancesCache.push(name);
		return name;
	}

	private Entry<String, List<Entry<String, String>>> replaceParameterByValue(CrySLRule rule,
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
				Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> producer = predicateConnections.stream()
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

					Optional<Entry<String, String>> preMatch = declaredVariables.stream()
							.filter(e -> (Utils.isSubType(e.getValue(), parameter.getValue()) || Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
					if (preMatch.isPresent()) {
						methodParameter = methodParameter.replace(parameter.getKey(), preMatch.get().getKey());
						continue;
					}

					Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> temp = toBeEnsuredPred; 
					toBeEnsuredPred = producer.get();
					final CrySLRule producerRule = (CrySLRule) producer.get().getValue().getKey();
					if(!testMethod.isValid()) {
						// even for invalid tests the method invocations are generated correctly for implicit rules
						testMethod.setValid(true);
						generateTest(producerRule, testClass, getValidTransitionFromStateMachine(producerRule.getUsagePattern()), testMethod, false);
						testMethod.setValid(false);
					} else {
						generateTest(producerRule, testClass, getValidTransitionFromStateMachine(producerRule.getUsagePattern()), testMethod, false);
					}
					toBeEnsuredPred = temp;

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
			String value = analyseConstraints(parameter, rule, testClass, methodNamdResultAssignment.substring(methodNamdResultAssignment.lastIndexOf(".") + 1));
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
						if (matchMethodParameters(cryslMethodParameters, meth.getParameterTypes())) {
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
							if (matchMethodParameters(cryslMethodParameters, cons.getParameterTypes())) {
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
	
	public void updateToBeEnsured(Entry<String, String> entry) {
		if (toBeEnsuredPred != null) {
			CrySLPredicate existing = toBeEnsuredPred.getKey();
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
					toBeEnsuredPred = new SimpleEntry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>(new CrySLPredicate(existing.getBaseObject(), existing
						.getPredName(), parameters, existing.isNegated(), existing.getConstraint()), toBeEnsuredPred.getValue());
				}
			}

		}
	}
	
	public String analyseConstraints(Entry<String, String> parameter, CrySLRule rule, TestClass testClass, String methodName) {
		List<ISLConstraint> constraints = rule.getConstraints().stream().filter(e -> e.getInvolvedVarNames().contains(parameter.getKey())).collect(Collectors.toList());
		
		for (ISLConstraint constraint : constraints) {
			// handle CrySLValueConstraint
			String value = resolveCrySLConstraint(rule, parameter, constraint, methodName);
			if (!value.isEmpty()) {
				if ("java.lang.String".equals(parameter.getValue())) {
					value = "\"" + value + "\"";
				} else if ("java.lang.String[]".equals(parameter.getValue())) {
					value = "new String[]{\"" + value + "\"}";
				} else if ("java.math.BigInteger".equals(parameter.getValue())) {
					value = "BigInteger.valueOf(" + value + ")";
					testClass.addImport("java.math.BigInteger");
				} else {
					ruleParameterCache.putIfAbsent(parameter.getKey(), value);
				}
				return value;
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