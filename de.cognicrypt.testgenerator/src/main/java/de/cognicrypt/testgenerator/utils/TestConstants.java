package de.cognicrypt.testgenerator.utils;

import java.util.Arrays;
import java.util.List;

import de.cognicrypt.core.Constants;

public class TestConstants extends Constants {

	public static final String PROJECT_NAME = "UsagePatternTests";
	public static final String SELECTED_RULENAMES_FILEPATH = "resources/selected_rules.txt";
	public static final List<String> PREDEFINED_PREDS = Arrays.asList("callTo", "noCallTo", "neverTypeOf", "length", "notHardCoded");
	public static final List<String> TEST_IMPORTS = Arrays.asList("org.junit.Test", "test.UsagePatternTestingFramework", "test.assertions.Assertions", "crypto.analysis.CrySLRulesetSelector.Ruleset");
}
