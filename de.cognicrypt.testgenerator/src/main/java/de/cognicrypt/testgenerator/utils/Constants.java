package de.cognicrypt.testgenerator.utils;

import java.util.Arrays;
import java.util.List;

public class Constants {

	public static final String PROJECT_NAME = "UsagePatternTests";
	public static final String SELECTED_RULENAMES_FILEPATH = "resources/selected_rules.txt";
	public static final String PATH_SEPARATOR = "/";
	public final static List<String> PREDEFINED_PREDS = Arrays.asList("callTo", "noCallTo", "neverTypeOf", "length", "notHardCoded");
}
