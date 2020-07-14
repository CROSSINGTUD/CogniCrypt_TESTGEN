package de.cognicrypt.testgenerator.generator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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

import org.eclipse.core.resources.IResource;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jdt.core.JavaModelException;

import crypto.rules.CrySLMethod;
import crypto.rules.CrySLObject;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.StateMachineGraph;
import crypto.rules.StateNode;
import crypto.rules.TransitionEdge;
import de.cognicrypt.codegenerator.generator.CodeGenCrySLRule;
import de.cognicrypt.codegenerator.generator.CodeHandler;
import de.cognicrypt.codegenerator.generator.CrySLBasedCodeGenerator;
import de.cognicrypt.codegenerator.generator.GeneratorClass;
import de.cognicrypt.codegenerator.generator.GeneratorMethod;
import de.cognicrypt.codegenerator.generator.RuleDependencyTree;
import de.cognicrypt.codegenerator.generator.StateMachineGraphAnalyser;
import de.cognicrypt.core.Constants;
import de.cognicrypt.utils.CrySLUtils;
import de.cognicrypt.testgenerator.Activator;
import de.cognicrypt.testgenerator.utils.TestUtils;
import de.cognicrypt.utils.DeveloperProject;
import de.cognicrypt.utils.Utils;

public class TestGenerator {

	static Logger debugLogger = Logger.getLogger(TestGenerator.class.getName());
	private IJavaProject javaProject;
	private IResource targetFile;
	private CrySLBasedCodeGenerator codeGenerator;
	private DeveloperProject developerProject;
	private static List<CrySLRule> rules;
	private static RuleDependencyTree rdt;
	private static int numberOfValidTestCases;
	private static int numberOfInvalidTestCases;

	private static TestGenerator testGenerator = new TestGenerator();

	private TestGenerator() {

	}
	
	static {
		debugLogger.info("Reading ruleset.");
		rules = CrySLUtils.readCrySLRules();
		debugLogger.info("Finished reading ruleset.");
		rdt = new RuleDependencyTree(rules);
	}

	void initialize() throws CoreException {
		debugLogger.setLevel(Level.INFO);
		this.javaProject = TestUtils.createJavaProject("UsagePatternTests");
	}

	public static TestGenerator getInstance() {
		return testGenerator;
	}

	public void generateTests() {
		try {
			initialize();
		} catch (CoreException e) {
			Activator.getDefault().logError(e, "Failed to initialize project");
		}
		
		File file = Utils.getResourceFromWithin("resources/selected_rules.txt", de.cognicrypt.testgenerator.Activator.PLUGIN_ID);
		List<String> selectedRules = new ArrayList<String>();
		try {
			BufferedReader bufferReader = new BufferedReader(new FileReader(file));
			try {
				String line;
				while ((line = bufferReader.readLine()) != null) {
					selectedRules.add(line);
				}
			} finally {
				bufferReader.close();
			}
		} catch (IOException e) {
			throw new RuntimeException("Failed to read from selected_rules.txt", e);
		} 
		
		for (CrySLRule curRule : rules) {
			numberOfValidTestCases = 0;
			numberOfInvalidTestCases = 0;
			// FIXME2 only for testing purpose
//			if(curRule.getClassName().equals("javax.crypto.spec.GCMParameterSpec")) {
			if(selectedRules.contains(curRule.getClassName())) {
				debugLogger.info("Creating tests for " + curRule.getClassName());
				String testClassName = TestUtils.retrieveOnlyClassName(curRule.getClassName()) + "Test";
				try {
					// FIXME2 this method is only retained because CrySLBasedCodeGenerator constructor requires targetFile. Or else templateClass values can be used to generate class
					
					this.targetFile = TestUtils.generateJavaClassInJavaProject(this.javaProject, "jca", testClassName);
					this.codeGenerator = new CrySLBasedCodeGenerator(targetFile);
					this.developerProject = this.codeGenerator.getDeveloperProject();
				} catch (JavaModelException e) {
					debugLogger.log(Level.SEVERE, "Unable to create " + testClassName + " class.");
					e.printStackTrace();
				}
				String genFolder = "";
				try {
					genFolder = this.developerProject.getProjectPath() + Constants.innerFileSeparator + this.developerProject
						.getSourcePath() + Constants.innerFileSeparator + "jca" + Constants.innerFileSeparator;
				} catch (CoreException e1) {
					Activator.getDefault().logError(e1);
				}
				
				Set<GeneratorClass> generatedClasses = new HashSet<GeneratorClass>();
				
				GeneratorTestClass templateClass = new GeneratorTestClass();
				templateClass.setPackageName("jca");
				templateClass.setModifier("public");
				templateClass.setClassName(testClassName);
				
				templateClass.addMethod(generateOverriddenMethods());
				
				Map<String, List<CrySLPredicate>> reliablePreds = new HashMap<String, List<CrySLPredicate>>();
				
				// NOTE2 In case of tests generation there is no template method which uses only subset of rules. Instead we
				// consider all rules which has direct path to current rule i.e. they generate the required predicate
				Iterator<CrySLRule> itr = rules.iterator();
				List<CrySLRule> relatedRules = new ArrayList<>();
				// NOTE2 Every rule has different predicate connections
				this.codeGenerator.setPredicateConnections(new ArrayList<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>>());
				CrySLRule curRule1 = curRule;
				while (itr.hasNext()) {
					CrySLRule nextRule = itr.next();
					// NOTE2 CrySLRule doesn't implement toEquals() method
					if(!curRule.getClassName().equals(nextRule.getClassName())) {
						// NOTE curRule depends on nextRule that ensures its required predicate
						if(rdt.hasDirectPath(nextRule, curRule)) {
							// NOTE4 avoid adding both PKIXBuilderParameters and PKIXParameters
							if(!isAdded(nextRule)) {
								this.codeGenerator.populatePredicateConnections(nextRule, curRule);
								relatedRules.add(nextRule);
								curRule = nextRule;
								itr = rules.listIterator();
							}
						}

					}
				}

				printPredicateConnections(curRule1);	
				Collections.reverse(relatedRules);

				String usedClass = curRule1.getClassName();
				StateMachineGraph stateMachine = curRule1.getUsagePattern();
				Iterator<List<TransitionEdge>> validTransitions = getValidTransitionsFromStateMachine(stateMachine);
				
				GeneratorTestMethod templateMethod = null;
				List<TransitionEdge> currentTransition = null;
				ArrayList<String> imports = null;
				Map<CrySLPredicate, Entry<CrySLRule, CrySLRule>> mayUsePreds = null;
				
				while(validTransitions.hasNext()) {
					templateMethod = generateMethod(true);
					templateClass.addMethod(templateMethod);

					populateMethod(templateClass, reliablePreds, relatedRules, usedClass, templateMethod);

					this.codeGenerator.setToBeEnsuredPred(new SimpleEntry(curRule1.getPredicates().get(0), new SimpleEntry(curRule1, null)));
					currentTransition = validTransitions.next();
					imports = new ArrayList<String>(this.codeGenerator.determineImports(currentTransition));
					mayUsePreds = this.codeGenerator.determineMayUsePreds(usedClass);

					generateMethodInvocations(templateClass, curRule1, templateMethod, currentTransition, mayUsePreds, imports, true, true);
				}
				
				// case 1 : only generate target rule object correctly => RequiredPredicateError
				if (relatedRules.size() > 0) {
					templateMethod = generateMethod(false);
					templateClass.addMethod(templateMethod);
					
					generateMethodInvocations(templateClass, curRule1, templateMethod, currentTransition, mayUsePreds, imports, true, false);
				}
				
				// case 2 : generate required objects correctly + target rule object incorrectly => IncompleteOperationError
				Iterator<List<TransitionEdge>> invalidTransitions = getInvalidTransitionsFromStateMachine(stateMachine);
				while(invalidTransitions.hasNext()) {
					templateMethod = generateMethod(false);
					templateClass.addMethod(templateMethod);

					populateMethod(templateClass, reliablePreds, relatedRules, usedClass, templateMethod);
					
//					this.codeGenerator.setToBeEnsuredPred(new SimpleEntry(curRule1.getPredicates().get(0), new SimpleEntry(curRule1, null)));
					currentTransition = invalidTransitions.next();
					imports = new ArrayList<String>(this.codeGenerator.determineImports(currentTransition));
					mayUsePreds = this.codeGenerator.determineMayUsePreds(usedClass);

					generateMethodInvocations(templateClass, curRule1, templateMethod, currentTransition, mayUsePreds, imports, true, false);
				}
				
				List<String> testImports = Arrays.asList(new String[]{"org.junit.Test", "test.UsagePatternTestingFramework", "test.assertions.Assertions", "crypto.analysis.CrySLRulesetSelector.Ruleset"});
				templateClass.addImports(testImports);
				generatedClasses.add(templateClass);
				CodeHandler codeHandler = new CodeHandler(generatedClasses);
				try {
					codeHandler.writeToDisk(genFolder);
				} catch (Exception e) {
					Activator.getDefault().logError(e, "Failed to write to disk.");
				}
			}
		}
		addAdditionalFiles("lib");
		debugLogger.info("Cleaning up generated project.");
		try {
			TestUtils.cleanUpProject(developerProject);
		} catch (CoreException e) {
			Activator.getDefault().logError(e, "Failed to clean up.");
		}
		debugLogger.info("Finished clean up.");
	}

	private Iterator<List<TransitionEdge>> getValidTransitionsFromStateMachine(StateMachineGraph stateMachine) {
		// analyse state machine
		StateMachineGraphAnalyser stateMachineGraphAnalyser = new StateMachineGraphAnalyser(stateMachine);
		ArrayList<List<TransitionEdge>> transitionsList;
		Iterator<List<TransitionEdge>> transitions = null;
		try {
			transitionsList = stateMachineGraphAnalyser.getTransitions();
			transitionsList.sort(new Comparator<List<TransitionEdge>>() {

				@Override
				public int compare(List<TransitionEdge> element1, List<TransitionEdge> element2) {
					return Integer.compare(element1.size(), element2.size());
				}
			});
			transitions = transitionsList.iterator();
		} catch (Exception e) {
			Activator.getDefault().logError(e);
		}
		return transitions;
	}

	private Iterator<List<TransitionEdge>> getInvalidTransitionsFromStateMachine(StateMachineGraph stateMachine) {
		// analyse state machine
		StateMachineGraphAnalyser stateMachineGraphAnalyser = new StateMachineGraphAnalyser(stateMachine);
		ArrayList<List<TransitionEdge>> transitionsList;
		Iterator<List<TransitionEdge>> transitions = null;
		try {
			transitionsList = stateMachineGraphAnalyser.getTransitions();
			ArrayList<List<TransitionEdge>> invalidTransitionsList = composeInvalidTransitions(transitionsList);
			invalidTransitionsList.sort(new Comparator<List<TransitionEdge>>() {

				@Override
				public int compare(List<TransitionEdge> element1, List<TransitionEdge> element2) {
					return Integer.compare(element1.size(), element2.size());
				}
			});
			transitions = invalidTransitionsList.iterator();
		} catch (Exception e) {
			Activator.getDefault().logError(e);
		}
		return transitions;
	}

	private ArrayList<List<TransitionEdge>> composeInvalidTransitions(ArrayList<List<TransitionEdge>> transitionsList) {
		LinkedHashSet<List<TransitionEdge>> resultantList = new LinkedHashSet<List<TransitionEdge>>();
		
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
		
		return new ArrayList<List<TransitionEdge>>(resultantList);
	}

	private GeneratorMethod generateOverriddenMethods() {
		GeneratorMethod method = new GeneratorMethod();
		method.setModifier("protected");
		method.setReturnType("Ruleset");
		method.setName("getRuleSet");
		method.addStatementToBody("return Ruleset.JavaCryptographicArchitecture;");
		return method;
	}

	public void generate(GeneratorTestClass templateClass, GeneratorTestMethod templateMethod,
			List<String> imports, ArrayList<String> methodInvocations, String instanceName, boolean isValid) {
		templateMethod.addStatementToBody("");
		for (String methodInvocation : methodInvocations) {
			templateMethod.addStatementToBody(methodInvocation);
		}
		
		CrySLPredicate predicate = codeGenerator.getToBeEnsuredPred().getKey();
		String param = predicate.getParameters().get(0).getName();
		
		if (isValid) {
			templateMethod.addStatementToBody("Assertions.mustBeInAcceptingState(" + instanceName + ");");

			if(param.equals("this"))
				templateMethod.addStatementToBody("Assertions.hasEnsuredPredicate(" + instanceName + ");");
			else
				templateMethod.addStatementToBody("Assertions.hasEnsuredPredicate(" + param + ");");
		} else {
			templateMethod.addStatementToBody("Assertions.mustNotBeInAcceptingState(" + instanceName + ");");

			if(param.equals("this"))
				templateMethod.addStatementToBody("Assertions.notHasEnsuredPredicate(" + instanceName + ");");
			else
				templateMethod.addStatementToBody("Assertions.notHasEnsuredPredicate(" + param + ");");
		}
		
		templateMethod.addExceptions(this.codeGenerator.getExceptions());
		templateClass.addImports(imports);
	}

	public void printPredicateConnections(CrySLRule rule) {
		System.out.print("PC : " + TestUtils.retrieveOnlyClassName(rule.getClassName()));
		List<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> connections = this.codeGenerator.getPredicateConnections();
		for (Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> c : connections) {
			CrySLPredicate key = c.getKey();
			Entry<CrySLRule, CrySLRule> value = c.getValue();
			System.out.print(" -> " + TestUtils.retrieveOnlyClassName(value.getKey().getClassName()));
		}
		System.out.println("\n");
	}

	public boolean isAdded(CrySLRule nextRule) {
		return this.codeGenerator.getPredicateConnections().stream().anyMatch(entry -> {
			return nextRule.getPredicates().stream().anyMatch(predicate -> {
				return predicate.getPredName().equals(entry.getKey().getPredName());
			});
		});
	}
	
	public void populateMethod(GeneratorTestClass templateClass, Map<String, List<CrySLPredicate>> reliablePreds,
			List<CrySLRule> relatedRules, String usedClass, GeneratorTestMethod templateMethod) {
		// NOTE for every rule we consider the list of related rules. For eg. SecureRandom (1st gen) -> PBEKeySpec -> SecretKeyFactory -> SecretKey (nth gen)
		for (CrySLRule rule : relatedRules) {
			boolean next = true;
			StateMachineGraph stateMachine = rule.getUsagePattern();
			Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> toBeEnsured = Optional.empty();

			toBeEnsured = this.codeGenerator.determineEnsurePreds(rule);

			Iterator<List<TransitionEdge>> transitions = this.codeGenerator.getTransitionsFromStateMachine(stateMachine);

			do {
				List<TransitionEdge> currentTransition = transitions.next();
				ArrayList<String> imports = new ArrayList<String>(this.codeGenerator.determineImports(currentTransition));
				// NOTE2 other imports have to be added later
				//						templateClass.addImports(imports);

				Map<CrySLPredicate, Entry<CrySLRule, CrySLRule>> mayUsePreds = this.codeGenerator.determineMayUsePreds(usedClass);

				// NOTE2 this won't work; many statements result in NullPointerExceptions
				//						CodeGenCrySLRule dummyRule = new CodeGenCrySLRule(rule, null, null);
				//						ArrayList<String> methodInvocations = this.codeGenerator.generateMethodInvocations(dummyRule, templateMethod, currentTransitions, mayUsePreds, imports, lastRule);

				boolean generated = generateMethodInvocations(templateClass, rule, templateMethod, currentTransition, mayUsePreds, imports, false, true);

				if (!generated) {
					continue;
				}

//				if (this.codeGenerator.getToBeEnsuredPred() != null && toBeEnsured.isPresent() && !toBeEnsured.get().getKey().getParameters().get(0)
//						.equals(this.codeGenerator.getToBeEnsuredPred().getKey().getParameters().get(0))) {
//					Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> originalPred = toBeEnsured.get();
//					int indexOf = this.codeGenerator.getPredicateConnections().indexOf(originalPred);
//					this.codeGenerator.getPredicateConnections().remove(indexOf);
//					this.codeGenerator.getPredicateConnections().add(indexOf, this.codeGenerator.getToBeEnsuredPred());
//				}

				reliablePreds.put(rule.getClassName(), rule.getPredicates());
				next = false;
			} while(next);
		}
	}

	public GeneratorTestMethod generateMethod(boolean isValid) {

		GeneratorTestMethod templateMethod = new GeneratorTestMethod();
		templateMethod.setModifier("public");
		templateMethod.setReturnType("void");
		if(isValid) {
			templateMethod.setName("validTest" + ++numberOfValidTestCases); // Final Format : cipherCorrectTest1, cipherIncorrectTest1 ...
		} else {
			templateMethod.setName("invalidTest" + ++numberOfInvalidTestCases);
		}
		return templateMethod;
	}

	// NOTE2 this method is re-created because TestGenerator doesn't use any template file. Hence there are no addParam, addReturnObj calls & declared variables.

	private boolean generateMethodInvocations(GeneratorTestClass templateClass, CrySLRule rule, GeneratorTestMethod useMethod, List<TransitionEdge> currentTransitions, Map<CrySLPredicate, Entry<CrySLRule, CrySLRule>> usablePreds, List<String> imports, boolean lastRule, boolean isValid) {
		Set<StateNode> killStatements = this.codeGenerator.extractKillStatements(rule);
		ArrayList<String> methodInvocations = new ArrayList<String>();
		List<String> localKillers = new ArrayList<String>();
		boolean ensures = false;

		Set<Entry<String, String>> useMethodVariables = new HashSet<Entry<String, String>>();
		Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> pre = new SimpleEntry<>(this.codeGenerator.getToBeEnsuredPred().getKey(), this.codeGenerator.getToBeEnsuredPred().getValue());

		StringBuilder instanceName = new StringBuilder();
		for (TransitionEdge transition : currentTransitions) {
			List<CrySLMethod> labels = transition.getLabel();
			Entry<CrySLMethod, Boolean> entry = this.codeGenerator.fetchEnsuringMethod(usablePreds, pre, labels, ensures);
			CrySLMethod method = entry.getKey();
			ensures = entry.getValue();
			String methodName = method.getMethodName();
			// NOTE stripping away the package and retaining only method name
			methodName = methodName.substring(methodName.lastIndexOf(".") + 1);

			// Determine parameter of method.
			List<Entry<String, String>> parameters = method.getParameters();
			StringBuilder sourceLineGenerator = this.codeGenerator.constructMethodCall(methodName, parameters);

			Class<?>[] methodParameter = this.codeGenerator.collectParameterTypes(parameters);

			try {
				this.codeGenerator.determineThrownExceptions(method.getMethodName().substring(0, method.getMethodName().lastIndexOf(".")), methodName, methodParameter, imports);
			} catch (NoSuchMethodException | SecurityException | ClassNotFoundException e) {
				Activator.getDefault().logError(e);
			}

			// NOTE2 why is generateSeed returned instead of nextBytes for SecureRandom.crysl
			String lastInvokedMethod = this.codeGenerator.getLastInvokedMethodName(currentTransitions).toString();

			Entry<String, List<Entry<String, String>>> methodInvocationWithUseMethodParameters = generateMethodInvocation(useMethod, lastInvokedMethod, imports, method, methodName,
					parameters, rule, sourceLineGenerator, lastRule, instanceName);
			
			useMethodVariables.addAll(methodInvocationWithUseMethodParameters.getValue());
			String methodInvocation = methodInvocationWithUseMethodParameters.getKey();
			// Add new generated method invocation
			if (!methodInvocation.isEmpty()) {
				if (killStatements.contains(transition.to())) {
					localKillers.add(methodInvocation);
				} else {
					methodInvocations.add(methodInvocation);
				}
				methodInvocation = "";
			}
		}
		
		useMethod.addVariablesToBody(useMethodVariables);

		if(lastRule) {
			if (this.codeGenerator.getToBeEnsuredPred() == null) {
				this.codeGenerator.getKills().addAll(localKillers);
			} else {
				this.codeGenerator.setToBeEnsuredPred(pre);
			}
			generate(templateClass, useMethod, imports, methodInvocations, instanceName.toString(), isValid);
			return true;
		} else {	
			if (this.codeGenerator.getToBeEnsuredPred() == null || ensures) {
				this.codeGenerator.getKills().addAll(localKillers);
				generate(templateClass, useMethod, imports, methodInvocations, instanceName.toString(), isValid);
				return true;
			} else {
				this.codeGenerator.setToBeEnsuredPred(pre);
				return false;
			}
		}
	}

	// NOTE2 this method is re-created because original version uses CodeGenCrySLRule
	private Entry<String, List<Entry<String, String>>> generateMethodInvocation(GeneratorMethod useMethod,
			String lastInvokedMethod, List<String> imports, CrySLMethod method, String methodName,
			List<Entry<String, String>> parameters, CrySLRule rule, StringBuilder currentInvokedMethod,
			boolean lastRule, StringBuilder instanceName1) {

		String methodInvocation = "";

		String className = rule.getClassName();
		String simpleName = TestUtils.retrieveOnlyClassName(className);
		String instanceName = simpleName.substring(0, 1).toLowerCase() + simpleName.substring(1);
		
		if(instanceName1.toString().isEmpty())	
			instanceName1.append(instanceName);
		
		// NOTE2 className is used because its later used by isSubType for resolving parameters based on the variables generated by TestGenerator
		if (currentInvokedMethod.substring(0, currentInvokedMethod.indexOf("(")).equals(simpleName)) {
			methodInvocation = className + " " + instanceName + " = new " + currentInvokedMethod;
		}
		else if (currentInvokedMethod.toString().contains("getInstance")) {
			currentInvokedMethod = new StringBuilder(currentInvokedMethod.substring(currentInvokedMethod.lastIndexOf("=") + 1).trim());
			methodInvocation = className + " " + instanceName + " = " + simpleName + "." + currentInvokedMethod;
		}
		else {
			// Does method have a return value?
			if (method.getRetObject() != null) {
				String returnValueType = method.getRetObject().getValue();
				boolean generated = false;
				String voidString = "void";

				// Determine lastInvokedMethod
				lastInvokedMethod = lastInvokedMethod.substring(lastInvokedMethod.lastIndexOf('.') + 1);

				if (lastRule) {
					// Last invoked method and return type is not equal to "void".
					if (methodName.equals(lastInvokedMethod) && !returnValueType.equals(voidString)) {
						methodInvocation = method.getRetObject().getValue() + " " + method.getRetObject().getKey() + " = " + instanceName + "." + currentInvokedMethod;
						generated = true;
					}
					// Last invoked method and return type is equal to "void".
					else if (methodName.equals(lastInvokedMethod) && returnValueType.equals(voidString)) {
						methodInvocation = instanceName + "." + currentInvokedMethod; // + "\nreturn " + instanceName + ";";
						generated = true;
					}
					// Not the last invoked method and return type is not equal to "void".
					else if (!methodName.equals(lastInvokedMethod) && !returnValueType.equals(voidString)) {
						methodInvocation = returnValueType + " " + method.getRetObject().getKey() + " = " + instanceName + "." + currentInvokedMethod;
						generated = true;
					}
				}
				if (!generated) {
					if (!returnValueType.equals(voidString)) {
						String simpleType = returnValueType.substring(returnValueType.lastIndexOf('.') + 1);
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
			} else {
				methodInvocation = instanceName + "." + currentInvokedMethod;
			}
		}
		
		return replaceParameterByValue(rule, useMethod, parameters, methodInvocation, imports);
	}

	private Entry<String, List<Entry<String, String>>> replaceParameterByValue(CrySLRule rule,
			GeneratorMethod useMethod, List<Entry<String, String>> parametersOfCall, String currentInvokedMethod,
			List<String> imports) {

		String methodNamdResultAssignment = currentInvokedMethod.substring(0, currentInvokedMethod.indexOf("("));
		String methodParameter = currentInvokedMethod.substring(currentInvokedMethod.indexOf("("), currentInvokedMethod.indexOf(")"));
		String appendix = currentInvokedMethod.substring(currentInvokedMethod.indexOf(")"), currentInvokedMethod.length());
		List<Entry<String, String>> parametersOfUseMethod = new ArrayList<Entry<String, String>>();
		List<Entry<String, String>> declaredVariables = useMethod.getDeclaredVariables();
		
		for (Entry<String, String> parameter : parametersOfCall) {
			
			List<Entry<String, String>> tmpVariables = new ArrayList<>();
			if (declaredVariables.size() > 0) {
				tmpVariables.addAll(declaredVariables);
			}

			Optional<Entry<String, String>> typeMatch = tmpVariables.stream()
				.filter(e -> (de.cognicrypt.utils.Utils.isSubType(e.getValue(), parameter.getValue()) || de.cognicrypt.utils.Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
			if (typeMatch.isPresent()) {
				this.codeGenerator.updateToBeEnsured(typeMatch.get());
				methodParameter = methodParameter.replace(parameter.getKey(), typeMatch.get().getKey());
				continue;
			}
			
			Optional<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> entry = this.codeGenerator.getPredicateConnections().stream().filter(
					e -> de.cognicrypt.utils.Utils.isSubType(e.getValue().getValue().getClassName(), rule.getClassName()) || de.cognicrypt.utils.Utils.isSubType(rule.getClassName(), e.getValue().getValue().getClassName()))
					.findFirst();
			if (entry.isPresent()) {
				final CrySLObject CrySLObject = (CrySLObject) entry.get().getKey().getParameters().get(0);
				if (!"this".equals(CrySLObject.getVarName())) {
					if ((de.cognicrypt.utils.Utils.isSubType(CrySLObject.getJavaType(), parameter.getValue()) || de.cognicrypt.utils.Utils.isSubType(parameter.getValue(), CrySLObject.getJavaType()))) {
						methodParameter = methodParameter.replace(parameter.getKey(), CrySLObject.getVarName());
						continue;
					}
				}
			}
			
			String name = this.codeGenerator.analyseConstraints(parameter, new CodeGenCrySLRule(rule, null, null), methodNamdResultAssignment.substring(methodNamdResultAssignment.lastIndexOf(".") + 1), imports);
			if (!name.isEmpty()) {
				// NOTE2 what if a method has two parameter both of which can be resolved from using CONSTRAINTS, then in that case wouldn't methodParameter overwritten?
				methodParameter = methodParameter.replace(parameter.getKey(), name);
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
				imports.add(value);
			}	

		}
		
		currentInvokedMethod = methodNamdResultAssignment + methodParameter + appendix;
		return new SimpleEntry<>(currentInvokedMethod, parametersOfUseMethod);
	}
	
	public boolean addAdditionalFiles(final String source) {
		if (source.isEmpty()) {
			return true;
		}
		try {
			File pathToAddFiles = TestUtils.getResourceFromWithin(source);
			if (pathToAddFiles == null || !pathToAddFiles.exists()) {
				return true;
			}

			final File[] members = pathToAddFiles.listFiles();
			if (members == null) {
				Activator.getDefault().logError(Constants.ERROR_MESSAGE_NO_ADDITIONAL_RES_DIRECTORY);
			}
			for (int i = 0; i < members.length; i++) {
				final File addFile = members[i];
				if (!this.codeGenerator.addAddtionalFile(addFile)) {
					return false;
				}
			}
		} catch (IOException | CoreException e) {
			Activator.getDefault().logError(e, "An error occured during library addition.");
			return false;
		}
		return true;
	}
}