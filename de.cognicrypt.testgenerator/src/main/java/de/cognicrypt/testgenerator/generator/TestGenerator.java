package de.cognicrypt.testgenerator.generator;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
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
	Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> toBeEnsuredPred = null;
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
//		CrySLEntityPool.getInstance();
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
			if(curRule.getClassName().equals("javax.crypto.Cipher")) {
//			if(selectedRules.contains(curRule.getClassName())) {
				LOGGER.info("Creating tests for " + curRule.getClassName());
				String className = Utils.retrieveOnlyClassName(curRule.getClassName());
				
				TestClass testClass = new TestClass(className);
				testClass.setPackageName("jca");
				testClass.setModifier("public");
				testClasses.add(testClass);
				
				Map<String, List<CrySLPredicate>> reliablePreds = Maps.newHashMap();
				populatePredicateConnections();
				
				// NOTE2 In case of tests generation there is no template method which uses only subset of rules. Instead we
				// consider all rules which has direct path to current rule i.e. they generate the required predicate
//				Iterator<CrySLRule> itr = rules.iterator();
//				List<CrySLRule> relatedRules = Lists.newArrayList();
//				// NOTE2 Every rule has different predicate connections
//				this.codeGenerator.setPredicateConnections(Lists.newArrayList());
//				CrySLRule curRule1 = curRule;
//				while (itr.hasNext()) {
//					CrySLRule nextRule = itr.next();
//					// NOTE2 CrySLRule doesn't implement toEquals() method
//					if(!curRule.getClassName().equals(nextRule.getClassName())) {
//						// NOTE curRule depends on nextRule that ensures its required predicate
//						if(rdt.hasDirectPath(nextRule, curRule)) {
//							// NOTE4 avoid adding both PKIXBuilderParameters and PKIXParameters
//							if(!isAdded(nextRule)) {
//								this.codeGenerator.populatePredicateConnections(nextRule, curRule);
//								relatedRules.add(nextRule);
//								curRule = nextRule;
//								itr = rules.listIterator();
//							}
//						}
//
//					}
//				}
//
//				printPredicateConnections(curRule1);	
//				Collections.reverse(relatedRules);

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
			for(int j = i+1; j < rules.size(); j++) {
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
//		// case 1 : only generate target rule object correctly => RequiredPredicateError
//		if (relatedRules.size() > 0) {
//			testMethod = generateMethod(false);
//			templateClass.addMethod(testMethod);
//			
//			generateMethodInvocations(testClass, curRule, testMethod, currentTransition, mayUsePreds, imports, true, false);
//		}
		
		// case 2 : generate required objects correctly + target rule object incorrectly => IncompleteOperationError
		Iterator<List<TransitionEdge>> invalidTransitions = getInvalidTransitionsFromStateMachine(curRule.getUsagePattern());
		while(invalidTransitions.hasNext()) {
			List<TransitionEdge> currentTransition = invalidTransitions.next();
			TestMethod testMethod = testClass.addTestMethod(false);
			
			Set<String> imports = Utils.determineImports(currentTransition);
			// NOTE2 other imports have to be added later
			testClass.addImports(imports);

			populateMethod(curRule, currentTransition, testMethod, testClass);
			
			
//			this.codeGenerator.setToBeEnsuredPred(new SimpleEntry(findEnsuringPredicate(curRule, currentTransition), new SimpleEntry(curRule, null)));
//			mayUsePreds = this.codeGenerator.determineMayUsePreds(usedClass);
//
//			generateMethodInvocations(templateClass, curRule, testMethod, currentTransition, mayUsePreds, imports, true, false);
		}
	}

	private void generateValidTests(CrySLRule curRule, TestClass testClass) {
//		Map<String, List<CrySLPredicate>> reliablePreds = Maps.newHashMap();
		Iterator<List<TransitionEdge>> validTransitions = getValidTransitionsFromStateMachine(curRule.getUsagePattern());
//		Map<CrySLPredicate, Entry<CrySLRule, CrySLRule>> mayUsePreds;
		while(validTransitions.hasNext()) {
			List<TransitionEdge> currentTransition = validTransitions.next();
			TestMethod testMethod = testClass.addTestMethod(true);
			
			Set<String> imports = Utils.determineImports(currentTransition);
			// NOTE2 other imports have to be added later
			testClass.addImports(imports);

			populateMethod(curRule, currentTransition, testMethod, testClass);

			
//			this.codeGenerator.setToBeEnsuredPred(new SimpleEntry(findEnsuringPredicate(curRule, currentTransition), new SimpleEntry(curRule, null)));
//			mayUsePreds = this.codeGenerator.determineMayUsePreds(curRule.getClassName());

//					generateMethodInvocations(templateClass, curRule1, templateMethod, currentTransition, mayUsePreds, imports, true, true);
		}
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
			ArrayList<List<TransitionEdge>> validTransitionsList = stateMachineGraphAnalyser.getTransitions();
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

	private Iterator<List<TransitionEdge>> getInvalidTransitionsFromStateMachine(StateMachineGraph stateMachine) {
		StateMachineGraphAnalyser stateMachineGraphAnalyser = new StateMachineGraphAnalyser(stateMachine);
		try {
			ArrayList<List<TransitionEdge>> invalidTransitionsList = composeInvalidTransitions(stateMachineGraphAnalyser.getTransitions());
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

	private ArrayList<List<TransitionEdge>> composeInvalidTransitions(ArrayList<List<TransitionEdge>> transitionsList) {
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
		CrySLPredicate predicate = this.toBeEnsuredPred.getKey();
		
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

//	private void printPredicateConnections(CrySLRule rule) {
//		System.out.print("PC : " + Utils.retrieveOnlyClassName(rule.getClassName()));
//		List<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> connections = this.predicateConnections;
//		for (Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> c : connections) {
//			CrySLPredicate key = c.getKey();
//			Entry<CrySLRule, CrySLRule> value = c.getValue();
//			System.out.print(" -> " + Utils.retrieveOnlyClassName(value.getKey().getClassName()));
//		}
//		System.out.println("\n");
//	}

//	private boolean isAdded(CrySLRule nextRule) {
//		return this.codeGenerator.getPredicateConnections().stream().anyMatch(entry -> {
//			return nextRule.getPredicates().stream().anyMatch(predicate -> {
//				return predicate.getPredName().equals(entry.getKey().getPredName());
//			});
//		});
//	}
	
	private void populateMethod(CrySLRule curRule, List<TransitionEdge> currentTransition, TestMethod testMethod, TestClass testClass) {
		// NOTE for every rule we consider the list of related rules. For eg. SecureRandom (1st gen) -> PBEKeySpec -> SecretKeyFactory -> SecretKey (nth gen)
//		for (CrySLRule rule : relatedRules) {
//			CrySLBasedCodeGenerator.clearRuleParameterCache();
//			StateMachineGraph stateMachine = curRule.getUsagePattern();
//			Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> toBeEnsured = this.codeGenerator.determineEnsurePreds(curRule);

//			Iterator<List<TransitionEdge>> transitions = this.codeGenerator.getTransitionsFromStateMachine(stateMachine);

//			while(transitions.hasNext()) {
//				List<TransitionEdge> currentTransition = transitions.next();

//				Map<CrySLPredicate, Entry<CrySLRule, CrySLRule>> mayUsePreds = this.codeGenerator.determineMayUsePreds(curRule.getClassName());

				// NOTE2 this won't work; many statements result in NullPointerExceptions
				//						CodeGenCrySLRule dummyRule = new CodeGenCrySLRule(rule, null, null);
				//						ArrayList<String> methodInvocations = this.codeGenerator.generateMethodInvocations(dummyRule, templateMethod, currentTransitions, mayUsePreds, imports, lastRule);

				generateMethodInvocations(curRule, testMethod, testClass, currentTransition);
				this.toBeEnsuredPred = new SimpleEntry(findEnsuringPredicate(curRule, currentTransition), new SimpleEntry(curRule, null));
				generateAssertions(curRule, testMethod);

//				if (!generated) {
//					continue;
//				}

//				if (this.codeGenerator.getToBeEnsuredPred() != null && toBeEnsured.isPresent() && !toBeEnsured.get().getKey().getParameters().get(0)
//						.equals(this.codeGenerator.getToBeEnsuredPred().getKey().getParameters().get(0))) {
//					Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> originalPred = toBeEnsured.get();
//					int indexOf = this.codeGenerator.getPredicateConnections().indexOf(originalPred);
//					this.codeGenerator.getPredicateConnections().remove(indexOf);
//					this.codeGenerator.getPredicateConnections().add(indexOf, this.codeGenerator.getToBeEnsuredPred());
//				}

//				reliablePreds.put(curRule.getClassName(), curRule.getPredicates());
//				break;
//			}
//		}
	}

	// NOTE2 this method is re-created because TestGenerator doesn't use any template file. Hence there are no addParam, addReturnObj calls & declared variables.

	private void generateMethodInvocations(CrySLRule rule, TestMethod testMethod, TestClass testClass, List<TransitionEdge> currentTransitions) {
//		Set<StateNode> killStatements = this.codeGenerator.extractKillStatements(rule);
		ArrayList<String> methodInvocations = Lists.newArrayList();
//		List<String> localKillers = Lists.newArrayList();
//		boolean ensures = false;

		Set<Entry<String, String>> useMethodVariables = Sets.newHashSet();
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

			// Determine parameter of method.
			StringBuilder sourceLineGenerator = constructMethodCall(method);

			try {
				Set<String> exceptions = determineThrownExceptions(method);
				testMethod.addExceptions(exceptions);
				testClass.addImports(exceptions);
			} catch (final SecurityException | ClassNotFoundException e) {
				Activator.getDefault().logError(e);
			}

			// NOTE2 why is generateSeed returned instead of nextBytes for SecureRandom.crysl
//			String lastInvokedMethod = getLastInvokedMethodName(currentTransitions);

			Entry<String, List<Entry<String, String>>> methodInvocationWithUseMethodParameters = generateMethodInvocation(testMethod, testClass, method, rule, sourceLineGenerator, instanceName);
			
			useMethodVariables.addAll(methodInvocationWithUseMethodParameters.getValue());
			String methodInvocation = methodInvocationWithUseMethodParameters.getKey();
			// Add new generated method invocation
			if (!methodInvocation.isEmpty()) {
//				if (killStatements.contains(transition.to())) {
//					localKillers.add(methodInvocation);
//				} else 
				{
					methodInvocations.add(methodInvocation);
				}
			}
		}
		
		testMethod.addVariablesToBody(useMethodVariables);
		testMethod.addStatementToBody("");
		for (String methodInvocation : methodInvocations) {
			testMethod.addStatementToBody(methodInvocation);
		}

//		if(lastRule) {
//			if (this.codeGenerator.getToBeEnsuredPred() == null) {
//				this.codeGenerator.getKills().addAll(localKillers);
//			} else {
//				this.codeGenerator.setToBeEnsuredPred(pre);
//			}
//			generateAssertions(testMethod, methodInvocations, instanceName.toString(), isValid);
//			return true;
//		} else {	
//			if (this.codeGenerator.getToBeEnsuredPred() == null || ensures) {
//				this.codeGenerator.getKills().addAll(localKillers);
//				generateAssertions(testMethod, methodInvocations, instanceName.toString(), isValid);
//				return true;
//			} else {
//				this.codeGenerator.setToBeEnsuredPred(pre);
//				return false;
//			}
//		}
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
		Set<Class<?>> exceptionClasses = new HashSet<Class<?>>();
		Set<String> exceptions = new HashSet<String>();
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

		//.getMethod(methodName, methodParameters).getExceptionTypes();
		for (Class<?> exception : exceptionClasses) {

			exceptions.add(exception.getName());

//			String exceptionClass = exception.getSimpleName();
//			if (!exceptions.contains(exceptionClass)) {
//				exceptions.add(exceptionClass);
//			}

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

	// NOTE2 this method is re-created because original version uses CodeGenCrySLRule
	private Entry<String, List<Entry<String, String>>> generateMethodInvocation(TestMethod testMethod,
			TestClass testClass, CrySLMethod method, CrySLRule rule, StringBuilder currentInvokedMethod, StringBuilder instanceName1) {

		String methodInvocation = "";

		String className = rule.getClassName();
		String simpleClassName = Utils.retrieveOnlyClassName(className);
		String instanceName = Character.toLowerCase(simpleClassName.charAt(0)) + simpleClassName.substring(1);

//		if(instanceName1.toString().isEmpty())	
//			instanceName1.append(instanceName);

		// 1. Constructor method calls
		// 2. Static method calls
		// 3. Instance method calls

		// 1. Constructor method call
		// NOTE2 className is used because its later used by isSubType for resolving parameters based on the variables generated by TestGenerator
		if (currentInvokedMethod.substring(0, currentInvokedMethod.indexOf("(")).equals(simpleClassName)) {
			methodInvocation = className + " " + instanceName + " = new " + currentInvokedMethod;
		}
		// Static method call
		else if (currentInvokedMethod.toString().contains("getInstance")) {
			currentInvokedMethod = new StringBuilder(currentInvokedMethod.substring(currentInvokedMethod.lastIndexOf("=") + 1).trim());
			methodInvocation = className + " " + instanceName + " = " + simpleClassName + "." + currentInvokedMethod;
		}
		// 3. Instance method call
		else {
			// Does method have a return value?
			if (method.getRetObject() != null) {
				String returnValueType = method.getRetObject().getValue();
				//				boolean generated = false;
				//				String voidString = "void";

				// Determine lastInvokedMethod
				//				lastInvokedMethod = lastInvokedMethod.substring(lastInvokedMethod.lastIndexOf('.') + 1);

				//				boolean lastRule = true;
				//				if (lastRule ) {
				//					String methodName = method.getMethodName();
				//					// Last invoked method and return type is not equal to "void".
				//					if (methodName .equals(lastInvokedMethod) && !returnValueType.equals(voidString)) {
				//						methodInvocation = method.getRetObject().getValue() + " " + method.getRetObject().getKey() + " = " + instanceName + "." + currentInvokedMethod;
				//						generated = true;
				//					}
				//					// Last invoked method and return type is equal to "void".
				//					else if (methodName.equals(lastInvokedMethod) && returnValueType.equals(voidString)) {
				//						methodInvocation = instanceName + "." + currentInvokedMethod; // + "\nreturn " + instanceName + ";";
				//						generated = true;
				//					}
				//					// Not the last invoked method and return type is not equal to "void".
				//					else if (!methodName.equals(lastInvokedMethod) && !returnValueType.equals(voidString)) {
				//						methodInvocation = returnValueType + " " + method.getRetObject().getKey() + " = " + instanceName + "." + currentInvokedMethod;
				//						generated = true;
				//					}
				//				}
				//				if (!generated) {
				if (!returnValueType.equals("void")) {
					String simpleType = Utils.retrieveOnlyClassName(returnValueType);
					if (Character.isUpperCase(simpleType.charAt(0))) {
						methodInvocation = returnValueType + " " + Character.toLowerCase(simpleType.charAt(0)) + simpleType
								.substring(1) + " = " + instanceName + "." + currentInvokedMethod;
					} else {
						methodInvocation = returnValueType + " " + method.getRetObject().getKey() + " = " + instanceName + "." + currentInvokedMethod;
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
		List<Entry<String, String>> parametersOfUseMethod = new ArrayList<Entry<String, String>>();
		List<Entry<String, String>> declaredVariables = testMethod.getDeclaredVariables();
		List<Entry<String, String>> parametersOfCall = crySLMethod.getParameters();
		
		for (Entry<String, String> parameter : parametersOfCall) {
			
			List<Entry<String, String>> tmpVariables = Lists.newArrayList();
			if (declaredVariables.size() > 0) {
				tmpVariables.addAll(declaredVariables);
			}

			Optional<Entry<String, String>> typeMatch = tmpVariables.stream()
				.filter(e -> (Utils.isSubType(e.getValue(), parameter.getValue()) || Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
			if (typeMatch.isPresent()) {
				updateToBeEnsured(typeMatch.get());
				methodParameter = methodParameter.replace(parameter.getKey(), typeMatch.get().getKey());
				continue;
			}
			
			Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> entry = this.predicateConnections.stream().filter(
					e -> Utils.isSubType(e.getValue().getValue().getClassName(), rule.getClassName()) || Utils.isSubType(rule.getClassName(), e.getValue().getValue().getClassName()))
					.findFirst();
			if (entry.isPresent()) {
				final CrySLObject crySLObject = (CrySLObject) entry.get().getKey().getParameters().get(0);
				if (!"this".equals(crySLObject.getVarName())) {
					if (declaredVariables.contains(new SimpleEntry<String, String>(crySLObject.getVarName(), crySLObject.getJavaType())) && (de.cognicrypt.utils.Utils.isSubType(crySLObject.getJavaType(), parameter.getValue()) || de.cognicrypt.utils.Utils.isSubType(parameter.getValue(), crySLObject.getJavaType()))) {
						methodParameter = methodParameter.replace(parameter.getKey(), crySLObject.getVarName());
						continue;
					}
				}
			}
			
			String name = analyseConstraints(parameter, rule, testClass, methodNamdResultAssignment.substring(methodNamdResultAssignment.lastIndexOf(".") + 1));
			if (!name.isEmpty()) {
				// NOTE2 what if a method has two parameter both of which can be resolved from using CONSTRAINTS, then in that case wouldn't methodParameter overwritten?
				methodParameter = methodParameter.replace(parameter.getKey(), name);
				continue;
			}
			
			// NOTE2 parameterCache gets populated in resolveCrySLConstraint. But this code is unreachable during test generation 
			if (TestGenerator.parameterCache.containsKey(parameter.getKey())) {
				methodParameter = methodParameter.replace(parameter.getKey(), TestGenerator.parameterCache.get(parameter.getKey()));
				continue;
			}

			// NOTE2 5.	If everything fails, then it add the param to the wrapped code param
			// NOTE2 this also takes care of _ parameters
			parametersOfUseMethod.add(parameter);
			if (parameter.getValue().contains(".")) {
				// If no value can be assigned add variable to the parameter list of the super method
				// Check type name for "."
				String value = parameter.getValue().replace('$', '.');
				value = value.replaceAll("[\\[\\]]","");
//				imports.add(value);
			}	

		}
		
		currentInvokedMethod = methodNamdResultAssignment + methodParameter + appendix;
		return new SimpleEntry<>(currentInvokedMethod, parametersOfUseMethod);
	}
	
	public void updateToBeEnsured(Entry<String, String> entry) {
		if (toBeEnsuredPred != null) {
			CrySLPredicate existing = toBeEnsuredPred.getKey();
			CrySLObject predicatePar = (CrySLObject) existing.getParameters().get(0);

			if (!"this".equals(predicatePar.getVarName())) {
				List<ICrySLPredicateParameter> parameters = new ArrayList<ICrySLPredicateParameter>();
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
	
	/**
	 * This method analyses ISLConstraints to determine possible valid values for variables.
	 * 
	 * @param methodName
	 * 
	 * @param constraints
	 *        List of constraints that are used for the analysis.
	 * @return
	 */
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