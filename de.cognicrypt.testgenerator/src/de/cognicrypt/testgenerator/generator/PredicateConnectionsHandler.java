package de.cognicrypt.testgenerator.generator;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.google.common.collect.Lists;

import crypto.rules.CrySLMethod;
import crypto.rules.CrySLObject;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.TransitionEdge;
import de.cognicrypt.codegenerator.generator.RuleDependencyTree;
import de.cognicrypt.testgenerator.utils.Utils;

public class PredicateConnectionsHandler {
	
	private List<CrySLRule> rules;
	private List<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> predicateConnections = Lists.newArrayList();
	
	public List<Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>>> getPredicateConnections() {
		return predicateConnections;
	}

	public PredicateConnectionsHandler(List<CrySLRule> rules) {
		this.rules = rules;
		populatePredicateConnections();
	}

	private void populatePredicateConnections() {
		RuleDependencyTree rdt = new RuleDependencyTree(rules);
		for (int i = 0; i < rules.size(); i++) {
			CrySLRule cRule = rules.get(i);
			for(int j = 0; j < rules.size(); j++) {
//				if(j == i)
//					continue;
				
				CrySLRule nRule = rules.get(j);
				if (rdt.hasDirectPath(cRule, nRule)) {
					populate(cRule, nRule);
				}
			}
		}
	}
	
	private void populate(CrySLRule curRule, CrySLRule nextRule) {
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
	
	public void printPredicateConnections() {
		for (Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> c : predicateConnections) {
			CrySLPredicate key = c.getKey();
			Entry<CrySLRule, CrySLRule> value = c.getValue();
			System.out.println(key + " : " + Utils.retrieveOnlyClassName(value.getKey().getClassName()) + " -> " + Utils.retrieveOnlyClassName(value.getValue().getClassName()));
		}
	}
}
