package de.cognicrypt.testgenerator.generator;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Stack;

import com.google.common.collect.Maps;

import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;

public class CacheManager {

	static Stack<String> instancesCache = new Stack<>();
	
	static Entry<CrySLPredicate, Entry<CrySLRule, CrySLRule>> toBeEnsuredPred = null;
	static Entry<CrySLPredicate, Boolean> ensuredValues = null;
	static Map<CrySLRule, List<String>> kills = Maps.newHashMap();
}
