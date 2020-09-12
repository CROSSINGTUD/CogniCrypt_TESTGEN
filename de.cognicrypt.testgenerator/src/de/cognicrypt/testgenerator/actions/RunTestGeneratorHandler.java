package de.cognicrypt.testgenerator.actions;

import java.time.Duration;
import java.time.Instant;
import java.util.logging.Logger;

import org.eclipse.core.commands.AbstractHandler;
import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.core.commands.ExecutionException;
import org.eclipse.ui.IEditorPart;
import org.eclipse.ui.IEditorReference;
import org.eclipse.ui.IWorkbenchPage;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.PlatformUI;

import de.cognicrypt.testgenerator.generator.TestGenerator;

public class RunTestGeneratorHandler extends AbstractHandler {

	private static final Logger LOGGER = Logger.getLogger(RunTestGeneratorHandler.class.getName());
	
	@Override
	public Object execute(ExecutionEvent event) throws ExecutionException {
		closeExistingEditors();
		Instant start = Instant.now();
		TestGenerator generator = TestGenerator.getInstance();
		generator.generateTests();
		Instant finish = Instant.now();
		long timeElapsed = Duration.between(start, finish).getSeconds();
		LOGGER.info("Test generation took " + timeElapsed + "seconds!");
		return event;
	}

	public void closeExistingEditors() {
		IWorkbenchWindow workbenchWindow = PlatformUI.getWorkbench().getActiveWorkbenchWindow();
		IWorkbenchPage page = workbenchWindow.getActivePage();
		IEditorReference[] editorRefs = page.getEditorReferences();
		for (int i = 0; i < editorRefs.length; i++) {
			IEditorPart editor = editorRefs[i].getEditor(true);
			page.closeEditor(editor, true);
		}
	}

}
