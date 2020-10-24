package de.cognicrypt.testgenerator.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Logger;

import com.google.common.base.Defaults;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import crypto.rules.CrySLMethod;
import crypto.rules.CrySLRule;
import crypto.rules.TransitionEdge;
import de.cognicrypt.testgenerator.Activator;
import soot.Scene;
import soot.Type;

public class Utils extends de.cognicrypt.utils.Utils {
	
	private static final Logger LOGGER = Logger.getLogger(Utils.class.getName());
	
	public static String retrieveOnlyClassName(String className) {
		className = className.replace('$', '.');
		String[] values = className.split("\\.");
		return values[values.length-1];
	}
	
	public static String getDefaultValue(String type) {

		switch(type) {
			case "byte":
				return Defaults.defaultValue(Byte.TYPE).toString();
			case "short":
				return Defaults.defaultValue(Short.TYPE).toString();
			case "int":
				return Defaults.defaultValue(Integer.TYPE).toString();
			case "long":
				return Defaults.defaultValue(Long.TYPE).toString();
			case "float":
				return Defaults.defaultValue(Float.TYPE).toString();
			case "double":
				return Defaults.defaultValue(Double.TYPE).toString();
			case "boolean":
				return Defaults.defaultValue(Boolean.TYPE).toString();
			default:
				throw new IllegalArgumentException("Type " + type + " not supported");
		}
	}
	
	public static File getResourceFromWithin(final String inputPath) {
		return Utils.getResourceFromWithin(inputPath, Activator.PLUGIN_ID);
	}
	
	public static Type getType(CrySLRule rule, String var) {
		List<TransitionEdge> transitions = Lists.newArrayList(
				rule.getUsagePattern().getAllTransitions());
		for (TransitionEdge transition : transitions) {
			List<CrySLMethod> methods = transition.getLabel();
			for (CrySLMethod method : methods) {
				List<Entry<String, String>> parameters = method.getParameters();
				for (Entry<String, String> parameter : parameters) {
					if (parameter.getKey().equals(var)) {
						Type retType = null;
						try {
							retType = Scene.v().getType(parameter.getValue());
						} catch (RuntimeException e) {
							retType = Scene.v().getTypeUnsafe(parameter.getValue());
						}
						return retType;
					}
				}

				Entry<String, String> ret = method.getRetObject();
				if (ret.getKey().equals(var)) {
					Type retType = null;
					try {
						retType = Scene.v().getType(ret.getValue());
					} catch (RuntimeException e) {
						retType = Scene.v().getTypeUnsafe(ret.getValue());
					}

					return retType;
				}
			}
		}
		return null;
	}
	
	public static List<String> getSelectedRules() {
		File file = Utils.getResourceFromWithin("resources/selected_rules.txt", de.cognicrypt.testgenerator.Activator.PLUGIN_ID);
		List<String> selectedRules = Lists.newArrayList();
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
		return selectedRules;
	}
	
	public static Class<?>[] collectParameterTypes(List<Entry<String, String>> parameters) {
		Class<?>[] methodParameter = new Class<?>[parameters.size()];
		int i = 0;
		List<String> primitiveTypes = Arrays.asList(new String[] { "int", "boolean", "short", "double", "float", "long", "byte", "int[]", "byte[]", "char[]" });

		for (Entry<String, String> parameter : parameters) {
			if (primitiveTypes.contains(parameter.getValue())) {
				Class<?> primitiveType = null;
				switch (parameter.getValue()) {
					case "int":
						primitiveType = int.class;
						break;
					case "double":
						primitiveType = double.class;
						break;
					case "boolean":
						primitiveType = boolean.class;
						break;
					case "float":
						primitiveType = float.class;
						break;
					case "byte":
						primitiveType = byte.class;
						break;
					case "byte[]":
						primitiveType = byte[].class;
						break;
					case "int[]":
						primitiveType = int[].class;
						break;
					case "char[]":
						primitiveType = char[].class;
						break;
					default:
						primitiveType = int.class;
				}
				methodParameter[i] = primitiveType;
				i++;
			} else {
				try {
					if(parameter.getValue().contains("AnyType")) {
						methodParameter[i] = AnyType.class;
					}
					else if(parameter.getValue().contains("[")) {
						String typeName = parameter.getValue().replaceAll("[\\[\\]]","");
						Class<?> className = Class.forName(typeName);
						methodParameter[i] = Array.newInstance(className, 0).getClass();
					}
					else {
						methodParameter[i] = Class.forName(parameter.getValue());
					}
					i++;
				} catch (ClassNotFoundException e) {
					Activator.getDefault().logError(e, "No class found for type: " + parameter.getValue().toString());
				}
			}
		}
		return methodParameter;
	}
	
	public static Set<String> determineImports(List<TransitionEdge> transitions) {
		Set<String> imports = new HashSet<String>();
		for (TransitionEdge transition : transitions) {
			String completeMethodName = transition.getLabel().get(0).getMethodName();
			imports.add(completeMethodName.substring(0, completeMethodName.lastIndexOf(".")));
			String retObjectType = transition.getLabel().get(0).getRetObject().getValue();
			if(retObjectType.contains("["))
				retObjectType = retObjectType.substring(0, retObjectType.indexOf('['));
			try {
				Class.forName(retObjectType);
				imports.add(retObjectType);
			} catch(ClassNotFoundException e) {
				continue;
			}	
		}
		return imports;
	}
	
	public static String preprocessImports(String imp) {
		String value = imp.replace('$', '.');
		value = value.replaceAll("[\\[\\]]","");
		return value;
	}
	
	// This method is needed because equals in TransitionEdge also takes StateNode for comparison.
	public static boolean isPresent(List<TransitionEdge> keyTransition, List<List<TransitionEdge>> resultantList) {
		
		for (List<TransitionEdge> transition : resultantList) {
			int length = 0;
			for (TransitionEdge edge : transition) {
				// Because some aggregates contain other aggregates
				// https://github.com/CROSSINGTUD/Crypto-API-Rules/blob/3b6f7c5690e513b127c8f733fd297395ddbd5355/JavaCryptographicArchitecture/src/Mac.crysl#L36
				if(length < keyTransition.size() && keyTransition.get(length).getLabel().containsAll(edge.getLabel())) {
					length++;
				}
				
				if(length == keyTransition.size() && length == transition.size())
					return true;
			}
		}
		return false;
	}
	
	public static File getResourceFromTestGen(final String inputPath) {
		return getResourceFromWithin(inputPath, Activator.PLUGIN_ID);
	}
	
	public static boolean matchMethodParameters(Class<?>[] methodParameters, Class<?>[] classes) {
		for (int i = 0; i < methodParameters.length; i++) {
			if (methodParameters[i].getName().equals("de.cognicrypt.testgenerator.utils.AnyType")) {
				continue;
			} else if (!methodParameters[i].equals(classes[i])) {
				return false;
			}
		}
		return true;
	}
	
	public static Set<String> determineThrownExceptions(CrySLMethod method) throws SecurityException, ClassNotFoundException {
		Set<Class<?>> exceptionClasses = Sets.newHashSet();
		Set<String> exceptions = Sets.newHashSet();
		Class<?>[] methodParameters = Utils.collectParameterTypes(method.getParameters());
		String className = method.getMethodName().substring(0, method.getMethodName().lastIndexOf("."));
		Method[] methods = Class.forName(className).getMethods();
		String methodName = method.getShortMethodName();
		for (Method meth : methods) {
			if (meth.getExceptionTypes().length > 0 && meth.getName().equals(methodName) && methodParameters.length == meth.getParameterCount()) {
				if (Utils.matchMethodParameters(methodParameters, meth.getParameterTypes())) {
					exceptionClasses.addAll(Arrays.asList(meth.getExceptionTypes()));
				}
			}
		}
		
		Constructor[] constructors = Class.forName(className).getConstructors();
		for (Constructor cons: constructors) {
			String fullyQualifiedName = cons.getName();
			String consName = Utils.retrieveOnlyClassName(fullyQualifiedName);
			if (cons.getExceptionTypes().length > 0 && consName.equals(methodName) && methodParameters.length == cons.getParameterCount()) {
				if (Utils.matchMethodParameters(methodParameters, cons.getParameterTypes())) {
					exceptionClasses.addAll((Collection<? extends Class<?>>) Arrays.asList(cons.getExceptionTypes()));
				}
			}
		}

		for (Class<?> exception : exceptionClasses) {
			exceptions.add(exception.getName());
		}
		return exceptions;
	}
}
