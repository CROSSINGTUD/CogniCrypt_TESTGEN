package de.cognicrypt.testgenerator.actions;

import org.eclipse.core.commands.AbstractHandler;
import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.core.commands.ExecutionException;

import de.cognicrypt.testgenerator.generator.TestGenerator;

public class RunTestGeneratorHandler extends AbstractHandler {

	@Override
	public Object execute(ExecutionEvent event) throws ExecutionException {
		TestGenerator generator = TestGenerator.getInstance();
		generator.generateTests();	
		return event;
	}

}
