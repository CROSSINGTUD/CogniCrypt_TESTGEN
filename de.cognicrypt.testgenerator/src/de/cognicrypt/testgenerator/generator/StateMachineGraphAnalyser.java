package de.cognicrypt.testgenerator.generator;

import java.util.ArrayList;
import java.util.List;

import crypto.rules.StateMachineGraph;
import crypto.rules.StateNode;
import crypto.rules.TransitionEdge;
import de.cognicrypt.utils.CrySLUtils;

public class StateMachineGraphAnalyser extends de.cognicrypt.codegenerator.generator.StateMachineGraphAnalyser {

	public StateMachineGraphAnalyser(StateMachineGraph stateMachine) {
		super(stateMachine);
	}

	public ArrayList<List<TransitionEdge>> getTransitionsUpto(StateNode node) {
		allTransitions = new ArrayList<List<TransitionEdge>>();

		List<TransitionEdge> edges = stateMachine.getEdges();
		List<TransitionEdge> initialTransitions = stateMachine.getInitialTransitions();
		for (TransitionEdge initialTransition : initialTransitions) {

			List<TransitionEdge> transitions = new ArrayList<TransitionEdge>();

			visitNode(edges, initialTransition, transitions, node);
		}

		return allTransitions;
	}

	private void visitNode(List<TransitionEdge> edges, TransitionEdge currentTransition, List<TransitionEdge> transitions, StateNode node) {
		List<TransitionEdge> transitionsToAdjacentNodes = new ArrayList<TransitionEdge>();
		List<TransitionEdge> transitionsWithNextTransition = new ArrayList<TransitionEdge>();

		transitionsWithNextTransition.addAll(transitions);
		transitionsWithNextTransition.add(currentTransition);

		usedTransitions.add(currentTransition.toString());

		transitionsToAdjacentNodes.addAll(CrySLUtils.getOutgoingEdges(stateMachine.getAllTransitions(), currentTransition.getRight(), currentTransition.getRight()));

		for (TransitionEdge transition : transitionsToAdjacentNodes) {

			if (!usedTransitions.contains(transition.toString())) {
				visitNode(edges, transition, transitionsWithNextTransition, node);
			}
		}

		if (currentTransition.getRight().getName().equals(node.getName())) {
			allTransitions.add(transitionsWithNextTransition);
		}
	}
}
