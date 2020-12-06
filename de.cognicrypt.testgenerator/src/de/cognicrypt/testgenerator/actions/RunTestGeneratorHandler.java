package de.cognicrypt.testgenerator.actions;

import java.time.Instant;
import java.util.concurrent.TimeUnit;
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
import de.cognicrypt.testgenerator.utils.Utils;

public class RunTestGeneratorHandler extends AbstractHandler {

	private static final Logger LOGGER = Logger.getLogger(RunTestGeneratorHandler.class.getName());
	
	@Override
	public Object execute(ExecutionEvent event) throws ExecutionException {
		closeExistingEditors();
		long startTime = System.currentTimeMillis();
		Runtime runtime = Runtime.getRuntime();
		TestGenerator generator = TestGenerator.getInstance();
		generator.generateTests();
		Instant finish = Instant.now();
		long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
		LOGGER.info("Test generation took " + TimeUnit.MILLISECONDS.toSeconds(elapsedTime) + " seconds!");
		long memory = runtime.totalMemory() - runtime.freeMemory();
		LOGGER.info("Test generation took " + Utils.bytesToMegabytes(memory) + " MB!");
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
