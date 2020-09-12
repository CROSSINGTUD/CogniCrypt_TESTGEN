package de.cognicrypt.testgenerator.utils;

import java.util.Arrays;
import java.util.List;

public class Constants extends de.cognicrypt.core.Constants {

	public static final String PROJECT_NAME = "UsagePatternTests";
	public static final String SELECTED_RULENAMES_FILEPATH = "resources/selected_rules.txt";
	public static final List<String> PREDEFINED_PREDS = Arrays.asList("callTo", "noCallTo", "neverTypeOf", "length", "notHardCoded");
	public static final List<String> TEST_IMPORTS = Arrays.asList("org.junit.Test", "test.UsagePatternTestingFramework", "test.assertions.Assertions", "crypto.analysis.CrySLRulesetSelector.Ruleset");
	public static final String TEST_PROJECT_RESOURCES_PATH = "resources";
}
