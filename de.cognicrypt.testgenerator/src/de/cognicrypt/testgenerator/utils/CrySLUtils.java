package de.cognicrypt.testgenerator.utils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import crypto.rules.CrySLCondPredicate;
import crypto.rules.CrySLRule;
import crypto.rules.StateNode;
import de.cognicrypt.core.Constants;

public class CrySLUtils extends de.cognicrypt.utils.CrySLUtils {

	public static List<CrySLRule> readCrySLRules() {
		return readCrySLRules(Utils.getResourceFromTestGen(Constants.RELATIVE_RULES_DIR).getAbsolutePath());
	}
	
	public static Set<StateNode> extractKillStatements(CrySLRule rule) {
		Set<StateNode> killStatements = rule.getPredicates().stream().filter(pred -> pred.isNegated() && pred instanceof CrySLCondPredicate)
			.map(e -> ((CrySLCondPredicate) e).getConditionalMethods()).reduce(new HashSet<>(), (a, b) -> {
				a.addAll(b);
				return a;
			});
		return killStatements;
	}
}
