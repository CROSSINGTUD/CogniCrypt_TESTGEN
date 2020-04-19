package de.cognicrypt.testgenerator.generator;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Currency;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;

import javax.swing.JDialog;
import javax.swing.JOptionPane;

import org.eclipse.core.resources.IResource;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jdt.core.JavaModelException;

import crypto.rules.CryptSLMethod;
import crypto.rules.CryptSLObject;
import crypto.rules.CryptSLPredicate;
import crypto.rules.CryptSLRule;
import crypto.rules.StateMachineGraph;
import crypto.rules.StateNode;
import crypto.rules.TransitionEdge;
import de.cognicrypt.codegenerator.Activator;
import de.cognicrypt.codegenerator.generator.CodeGenCrySLRule;
import de.cognicrypt.codegenerator.generator.CodeHandler;
import de.cognicrypt.codegenerator.generator.CrySLBasedCodeGenerator;
import de.cognicrypt.codegenerator.generator.GeneratorClass;
import de.cognicrypt.codegenerator.generator.GeneratorMethod;
import de.cognicrypt.codegenerator.generator.RuleDependencyTree;
import de.cognicrypt.core.Constants;
import de.cognicrypt.testgenerator.utils.Utils;
import de.cognicrypt.utils.DeveloperProject;

public class TestGenerator {

	private IJavaProject javaProject;
	private IResource targetFile;
	private CrySLBasedCodeGenerator codeGenerator;
	private DeveloperProject developerProject;
	private List<CryptSLRule> rules;
	private RuleDependencyTree rdt;

	private static TestGenerator testGenerator = new TestGenerator();

	private TestGenerator() {

	}

	void initialize() throws CoreException {
		this.javaProject = Utils.createJavaProject("UsagePatternTests");
		this.rules = de.cognicrypt.utils.Utils.readCrySLRules();
		this.rdt = new RuleDependencyTree(this.rules);
	}

	public static TestGenerator getInstance() {
		return testGenerator;
	}

	public void generateTests() {
		try {
			initialize();
		} catch (CoreException e1) {
			System.out.println("Failed to initialize project");
			e1.printStackTrace();
		}
		JOptionPane optionPane = new JOptionPane("CogniCrypt is now generating testcases based on CrySL rules into project " + this.javaProject.getElementName() + ". This should take no longer than a few seconds.", JOptionPane.INFORMATION_MESSAGE, JOptionPane.DEFAULT_OPTION, null, new Object[] {}, null);
		JDialog waitingDialog = optionPane.createDialog("Generating Testcases");
		waitingDialog.setModal(false);
		waitingDialog.setVisible(true);
		
		List<String> selectedRules = new ArrayList<String>(Arrays.asList("java.security.MessageDigest", "java.security.SecureRandom", 
				"javax.crypto.SecretKey", "javax.crypto.spec.SecretKeySpec", "javax.crypto.KeyGenerator", "javax.crypto.SecretKeyFactory",
				"java.security.KeyStore", "javax.crypto.spec.DHParameterSpec", "javax.net.ssl.TrustManagerFactory"));
		
		for (CryptSLRule curRule : rules) {
			// FIXME2 only for testing purpose
//			if(curRule.getClassName().equals("java.security.MessageDigest")) {
			if(selectedRules.contains(curRule.getClassName())) {
//			if(curRule.getClassName().equals("java.security.MessageDigest") || curRule.getClassName().equals("java.security.SecureRandom") || curRule.getClassName().equals("javax.crypto.SecretKey") || curRule.getClassName().equals("javax.crypto.spec.SecretKeySpec") || curRule.getClassName().equals("javax.crypto.KeyGenerator") || curRule.getClassName().equals("javax.crypto.SecretKeyFactory")) {
//			if(!(curRule.getClassName().equals("javax.crypto.Cipher") || curRule.getClassName().equals("javax.crypto.Mac") || curRule.getClassName().equals("javax.crypto.spec.PBEKeySpec"))) {
				String testClassName = Utils.retrieveOnlyClassName(curRule.getClassName()) + "Test";
				try {
					// FIXME2 this method is only retained because CrySLBasedCodeGenerator constructor requires targetFile. Or else templateClass values can be used to generate class
					
					this.targetFile = Utils.generateJavaClassInJavaProject(this.javaProject, "jca", testClassName);
					this.codeGenerator = new CrySLBasedCodeGenerator(targetFile);
					this.developerProject = this.codeGenerator.getDeveloperProject();
				} catch (JavaModelException e) {
					System.out.println("Unable to create " + testClassName + " class.");
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
				
				GeneratorClass templateClass = new GeneratorClass();
				templateClass.setPackageName("jca");
				templateClass.setModifier("public");
				templateClass.setClassName(testClassName);
				GeneratorMethod templateMethod = new GeneratorMethod();
				templateClass.addMethod(templateMethod);
				templateMethod.setModifier("public");
				templateMethod.setReturnType("void");
				templateMethod.setName("testMethod"); // Final Format : cipherCorrectTest1, cipherIncorrectTest1 ...
				Map<String, List<CryptSLPredicate>> reliablePreds = new HashMap<String, List<CryptSLPredicate>>();
				
				// NOTE2 In case of tests generation there is no template method which uses only subset of rules. Instead we
				// consider all rules which has direct path to current rule i.e. they generate the required predicate
				Iterator<CryptSLRule> itr = rules.iterator();
				List<CryptSLRule> relatedRules = new ArrayList<>();
				relatedRules.add(curRule);
				// NOTE2 Every rule has different predicate connections
				this.codeGenerator.setPredicateConnections(new ArrayList<Entry<CryptSLPredicate, Entry<CryptSLRule, CryptSLRule>>>());
				while (itr.hasNext()) {
					CryptSLRule nextRule = itr.next();
					// NOTE2 CryptSLRule doesn't implement toEquals() method
					if(!curRule.getClassName().equals(nextRule.getClassName())) {
						// NOTE curRule depends on nextRule that ensures its required predicate
						if(rdt.hasDirectPath(nextRule, curRule)) {
							this.codeGenerator.populatePredicateConnections(nextRule, curRule);
							relatedRules.add(nextRule);
							curRule = nextRule;
							itr = rules.iterator();
						}

					}
				}

				Collections.reverse(relatedRules);
				
				String usedClass = relatedRules.get(relatedRules.size() - 1).getClassName();

				// NOTE for every rule we consider the list of related rules. For eg. SecureRandom (1st gen) -> PBEKeySpec -> SecretKeyFactory -> SecretKey (nth gen)
				for (CryptSLRule rule : relatedRules) {
					boolean next = true;
					boolean lastRule = relatedRules.get(relatedRules.size() - 1).equals(rule);
					StateMachineGraph stateMachine = rule.getUsagePattern();
					Optional<Entry<CryptSLPredicate, Entry<CryptSLRule, CryptSLRule>>> toBeEnsured = Optional.empty();
					
					if(!lastRule)
						toBeEnsured = this.codeGenerator.determineEnsurePreds(rule);
					else {
						// FIXME2 to be implemented without retObj
						this.codeGenerator.setToBeEnsuredPred(new SimpleEntry(rule.getPredicates().get(0), new SimpleEntry(rule, null)));
					}
					
					Iterator<List<TransitionEdge>> transitions = this.codeGenerator.getTransitionsFromStateMachine(stateMachine);

					do {
						List<TransitionEdge> currentTransition = transitions.next();
						ArrayList<String> imports = new ArrayList<String>(this.codeGenerator.determineImports(currentTransition));
						// NOTE2 other imports have to be added later
//						templateClass.addImports(imports);

						Map<CryptSLPredicate, Entry<CryptSLRule, CryptSLRule>> mayUsePreds = this.codeGenerator.determineMayUsePreds(usedClass);

						// NOTE2 this won't work; many statements result in NullPointerExceptions
						//						CodeGenCrySLRule dummyRule = new CodeGenCrySLRule(rule, null, null);
						//						ArrayList<String> methodInvocations = this.codeGenerator.generateMethodInvocations(dummyRule, templateMethod, currentTransitions, mayUsePreds, imports, lastRule);

						ArrayList<String> methodInvocations = generateMethodInvocations(rule, templateMethod, currentTransition, mayUsePreds, imports, lastRule);

						if (methodInvocations.isEmpty()) {
							continue;
						}

						if (this.codeGenerator.getToBeEnsuredPred() != null && toBeEnsured.isPresent() && !toBeEnsured.get().getKey().getParameters().get(0)
							.equals(this.codeGenerator.getToBeEnsuredPred().getKey().getParameters().get(0))) {
							Entry<CryptSLPredicate, Entry<CryptSLRule, CryptSLRule>> originalPred = toBeEnsured.get();
							int indexOf = this.codeGenerator.getPredicateConnections().indexOf(originalPred);
							this.codeGenerator.getPredicateConnections().remove(indexOf);
							this.codeGenerator.getPredicateConnections().add(indexOf, this.codeGenerator.getToBeEnsuredPred());
						}

						templateMethod.addStatementToBody("");
						for (String methodInvocation : methodInvocations) {
							templateMethod.addStatementToBody(methodInvocation);
						}
						
						templateMethod.addExceptions(this.codeGenerator.getExceptions());
						templateClass.addImports(imports);

						reliablePreds.put(rule.getClassName(), rule.getPredicates());
						next = false;
					} while(next);
				}
				generatedClasses.add(templateClass);
				CodeHandler codeHandler = new CodeHandler(generatedClasses);
				try {
					codeHandler.writeToDisk(genFolder);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	// NOTE2 this method is re-created because TestGenerator doesn't use any template file. Hence there are no addParam, addReturnObj calls & declared variables.

	private ArrayList<String> generateMethodInvocations(CryptSLRule rule, GeneratorMethod useMethod, List<TransitionEdge> currentTransitions, Map<CryptSLPredicate, Entry<CryptSLRule, CryptSLRule>> usablePreds, List<String> imports, boolean lastRule) {
		Set<StateNode> killStatements = this.codeGenerator.extractKillStatements(rule);
		ArrayList<String> methodInvocations = new ArrayList<String>();
		List<String> localKillers = new ArrayList<String>();
		boolean ensures = false;

		List<Entry<String, String>> useMethodParameters = new ArrayList<Entry<String, String>>();
		Entry<CryptSLPredicate, Entry<CryptSLRule, CryptSLRule>> pre = new SimpleEntry<>(this.codeGenerator.getToBeEnsuredPred().getKey(), this.codeGenerator.getToBeEnsuredPred().getValue());

		for (TransitionEdge transition : currentTransitions) {
			List<CryptSLMethod> labels = transition.getLabel();
			Entry<CryptSLMethod, Boolean> entry = this.codeGenerator.fetchEnsuringMethod(usablePreds, pre, labels, ensures);
			CryptSLMethod method = entry.getKey();
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
					parameters, rule, sourceLineGenerator, lastRule);
			
			useMethodParameters.addAll(methodInvocationWithUseMethodParameters.getValue());
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

		if (this.codeGenerator.getToBeEnsuredPred() == null || ensures) {
			this.codeGenerator.kills.addAll(localKillers);
			for (Entry<String, String> par : useMethodParameters) {
//				if(par.getValue().contains("."))
//					par.setValue(par.getValue().substring(par.getValue().lastIndexOf(".") + 1));
				useMethod.addParameter(par);
			}
			return methodInvocations;
		} else {
			this.codeGenerator.setToBeEnsuredPred(pre);
			return new ArrayList<String>();
		}	
	}

	// NOTE2 this method is re-created because original version uses CodeGenCrySLRule
	private Entry<String, List<Entry<String, String>>> generateMethodInvocation(GeneratorMethod useMethod,
			String lastInvokedMethod, List<String> imports, CryptSLMethod method, String methodName,
			List<Entry<String, String>> parameters, CryptSLRule rule, StringBuilder currentInvokedMethod,
			boolean lastRule) {

		String methodInvocation = "";

		String className = rule.getClassName();
		String simpleName = className.substring(className.lastIndexOf('.') + 1);
		String instanceName = simpleName.substring(0, 1).toLowerCase() + simpleName.substring(1);
		
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
						methodInvocation = returnValueType + " = " + instanceName + "." + currentInvokedMethod;
						generated = true;
					}
				}
				if (!generated) {
					if (!returnValueType.equals(voidString)) {
						String simpleType = returnValueType.substring(returnValueType.lastIndexOf('.') + 1);
						if (Character.isUpperCase(simpleType.charAt(0))) {
							methodInvocation = simpleType + " " + Character.toLowerCase(simpleType.charAt(0)) + simpleType
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

	private Entry<String, List<Entry<String, String>>> replaceParameterByValue(CryptSLRule rule,
			GeneratorMethod useMethod, List<Entry<String, String>> parametersOfCall, String currentInvokedMethod,
			List<String> imports) {

		String methodNamdResultAssignment = currentInvokedMethod.substring(0, currentInvokedMethod.indexOf("("));
		String methodParameter = currentInvokedMethod.substring(currentInvokedMethod.indexOf("("), currentInvokedMethod.indexOf(")"));
		String appendix = currentInvokedMethod.substring(currentInvokedMethod.indexOf(")"), currentInvokedMethod.length());
		List<Entry<String, String>> parametersOfUseMethod = new ArrayList<Entry<String, String>>();
		List<Entry<String, String>> declaredVariables = useMethod.getDeclaredVariables();
		
		for (Entry<String, String> parameter : parametersOfCall) {
			Optional<Entry<CryptSLPredicate, Entry<CryptSLRule, CryptSLRule>>> entry = this.codeGenerator.getPredicateConnections().stream().filter(
					e -> de.cognicrypt.utils.Utils.isSubType(e.getValue().getValue().getClassName(), rule.getClassName()) || de.cognicrypt.utils.Utils.isSubType(rule.getClassName(), e.getValue().getValue().getClassName()))
					.findFirst();
			if (entry.isPresent()) {
				final CryptSLObject cryptSLObject = (CryptSLObject) entry.get().getKey().getParameters().get(0);
				if (!"this".equals(cryptSLObject.getVarName())) {
					if ((de.cognicrypt.utils.Utils.isSubType(cryptSLObject.getJavaType(), parameter.getValue()) || de.cognicrypt.utils.Utils.isSubType(parameter.getValue(), cryptSLObject.getJavaType()))) {
						methodParameter = methodParameter.replace(parameter.getKey(), cryptSLObject.getVarName());
						continue;
					}
				}
			}
			
			List<Entry<String, String>> tmpVariables = new ArrayList<>();
			if (declaredVariables.size() > 0) {
				tmpVariables.add(declaredVariables.get(declaredVariables.size() - 1));
			}

			Optional<Entry<String, String>> typeMatch = tmpVariables.stream()
				.filter(e -> (de.cognicrypt.utils.Utils.isSubType(e.getValue(), parameter.getValue()) || de.cognicrypt.utils.Utils.isSubType(parameter.getValue(), e.getValue()))).findFirst();
			if (typeMatch.isPresent()) {
				this.codeGenerator.updateToBeEnsured(typeMatch.get());
				methodParameter = methodParameter.replace(parameter.getKey(), typeMatch.get().getKey());
				continue;
			}
			
			String name = this.codeGenerator.analyseConstraints(parameter, new CodeGenCrySLRule(rule, null, null), methodNamdResultAssignment.substring(methodNamdResultAssignment.lastIndexOf(".") + 1));
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
				imports.add(parameter.getValue());
			}	

		}
		
		currentInvokedMethod = methodNamdResultAssignment + methodParameter + appendix;
		return new SimpleEntry<>(currentInvokedMethod, parametersOfUseMethod);
	}
}
