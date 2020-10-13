package de.cognicrypt.testgenerator.generator;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.Map.Entry;

import com.google.common.collect.Lists;

import crypto.rules.CrySLCondPredicate;
import crypto.rules.CrySLMethod;
import crypto.rules.CrySLObject;
import crypto.rules.StateMachineGraph;
import crypto.rules.StateNode;
import crypto.rules.TransitionEdge;
import de.cognicrypt.testgenerator.Activator;
import de.cognicrypt.testgenerator.utils.Utils;

public class FSMHandler {
	
	private StateMachineGraph stateMachine;
	
	public FSMHandler(StateMachineGraph stateMachine) {
		this.stateMachine = stateMachine;
	}
	
	public Iterator<List<TransitionEdge>> getValidTransitionsFromStateMachine() {
		try {
			return getTransitionsFromStateMachine();
		} catch (Exception e) {
			Activator.getDefault().logError(e);
		}
		return null;
	}
	
	public List<TransitionEdge> getValidTransitionFromStateMachine() {
		try {
			Iterator<List<TransitionEdge>> validTransitions = getTransitionsFromStateMachine();
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

	private Iterator<List<TransitionEdge>> getTransitionsFromStateMachine() throws Exception {
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

	public Iterator<List<TransitionEdge>> getInvalidTransitionsFromStateMachine() {
		try {
			List<List<TransitionEdge>> invalidTransitionsList = composeInvalidTransitions();
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

	private List<List<TransitionEdge>> composeInvalidTransitions() throws Exception {
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
	
	static Entry<CrySLMethod, Boolean> fetchEnsuringMethod(TransitionEdge transition, boolean ensures) {
		List<CrySLMethod> labels = transition.getLabel();
		
		if(TestGenerator.toBeEnsuredPred.getKey() == null) {
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
	
	static CrySLMethod fetchCorrespondingMethod(TransitionEdge transition, Set<CrySLObject> set) {
		
		if(TestGenerator.toBeEnsuredPred.getKey() instanceof CrySLCondPredicate) {
			for(StateNode node : ((CrySLCondPredicate) TestGenerator.toBeEnsuredPred.getKey()).getConditionalMethods()) {
				if(node.getName().equals(transition.getRight().getName()))
					return transition.getLabel().get(0);
			}
		}
		
		CrySLObject objectOfPred = (CrySLObject) TestGenerator.toBeEnsuredPred.getKey().getParameters().get(0);
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
}
