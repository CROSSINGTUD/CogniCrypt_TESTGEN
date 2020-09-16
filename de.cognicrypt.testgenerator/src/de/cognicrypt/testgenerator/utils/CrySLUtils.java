package de.cognicrypt.testgenerator.utils;

import java.util.List;

import crypto.rules.CrySLRule;
import de.cognicrypt.core.Constants;

public class CrySLUtils extends de.cognicrypt.utils.CrySLUtils {

	public static List<CrySLRule> readCrySLRules() {
		return readCrySLRules(Utils.getResourceFromTestGen(Constants.RELATIVE_RULES_DIR).getAbsolutePath());
	}
}
