package de.cognicrypt.testgenerator.generator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.logging.Logger;

import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IFolder;
import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.IProjectDescription;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.resources.IWorkspaceRoot;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.jdt.core.IClasspathEntry;
import org.eclipse.jdt.core.ICompilationUnit;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jdt.core.IPackageFragmentRoot;
import org.eclipse.jdt.core.JavaCore;
import org.eclipse.jdt.launching.IVMInstall;
import org.eclipse.jdt.launching.JavaRuntime;
import org.eclipse.jdt.launching.LibraryLocation;
import org.eclipse.jdt.ui.actions.FormatAllAction;
import org.eclipse.ui.IEditorPart;
import org.eclipse.ui.ide.IDE;

import com.google.common.collect.Lists;

import de.cognicrypt.core.Constants;
import de.cognicrypt.testgenerator.Activator;
import de.cognicrypt.testgenerator.test.TestClass;
import de.cognicrypt.testgenerator.test.TestProject;
import de.cognicrypt.testgenerator.utils.Utils;
import de.cognicrypt.utils.DeveloperProject;
import de.cognicrypt.utils.UIUtils;

public class CodeHandler {
	
	private static final Logger LOGGER = Logger.getLogger(CodeHandler.class.getName());
	
	private static IJavaProject jProject;
	private static DeveloperProject dProject;
	
	public static File writeToDisk(TestProject testProject) throws Exception {

		File fileOnDisk = new File(dProject.getProjectPath() + Constants.innerFileSeparator + dProject.getSourcePath() + Constants.innerFileSeparator + "jca" + Constants.innerFileSeparator);
		fileOnDisk.mkdirs();
		for (TestClass toBeGeneratedClass : testProject.getTestClasses()) {
			String path = fileOnDisk.getAbsolutePath() + Constants.outerFileSeparator + toBeGeneratedClass.getClassName() + ".java";
			try (FileOutputStream fileOutputStream = new FileOutputStream(path)) {
				fileOutputStream.write(toBeGeneratedClass.toString().getBytes("UTF-8"));
			} catch (Exception e) {
				throw new Exception("Writing source code to file failed.");
			}
			toBeGeneratedClass.setSourceFile(new File(path));
		}

		return fileOnDisk;
	}
	
	/**
	 * This method creates a empty JavaProject in the current workspace
	 * 
	 * @param projectName for the JavaProject
	 * @return new created JavaProject
	 * @throws CoreException
	 */
	public static void createJavaProject(final String projectName) throws CoreException {

		LOGGER.info("Creating " + projectName + " project.");
		
		final IWorkspaceRoot workSpaceRoot = ResourcesPlugin.getWorkspace().getRoot();
		deleteProject(workSpaceRoot.getProject(projectName));

		final IProject project = workSpaceRoot.getProject(projectName);
		project.create(null);
		project.open(null);

		final IProjectDescription description = project.getDescription();
		description.setNatureIds(new String[] {JavaCore.NATURE_ID});
		project.setDescription(description, null);

		jProject = JavaCore.create(project);

		final IFolder binFolder = project.getFolder("bin");
		binFolder.create(false, true, null);
		jProject.setOutputLocation(binFolder.getFullPath(), null);

		final List<IClasspathEntry> entries = Lists.newArrayList();
		final IVMInstall vmInstall = JavaRuntime.getDefaultVMInstall();
		final LibraryLocation[] locations = JavaRuntime.getLibraryLocations(vmInstall);
		for (final LibraryLocation element : locations) {
			entries.add(JavaCore.newLibraryEntry(element.getSystemLibraryPath(), null, null));
		}
		// add libs to project class path
		jProject.setRawClasspath(entries.toArray(new IClasspathEntry[entries.size()]), null);

		final IFolder sourceFolder = project.getFolder("src");
		sourceFolder.create(false, true, null);

		final IPackageFragmentRoot packageRoot = jProject.getPackageFragmentRoot(sourceFolder);
		final IClasspathEntry[] oldEntries = jProject.getRawClasspath();
		final IClasspathEntry[] newEntries = new IClasspathEntry[oldEntries.length + 1];
		System.arraycopy(oldEntries, 0, newEntries, 0, oldEntries.length);
		newEntries[oldEntries.length] = JavaCore.newSourceEntry(packageRoot.getPath());
		jProject.setRawClasspath(newEntries, null);
		
		LOGGER.info("Finished creating " + projectName + " project.");
		
		dProject = new DeveloperProject(jProject.getProject());
		addAdditionalFiles("lib");
	}
	
	private static boolean addAdditionalFiles(final String source) {
		if (source.isEmpty()) {
			return true;
		}
		File pathToAddFiles = Utils.getResourceFromWithin(source);
		if (pathToAddFiles == null || !pathToAddFiles.exists()) {
			return true;
		}

		final File[] members = pathToAddFiles.listFiles();
		if (members == null) {
			Activator.getDefault().logError("No directory for additional resources found.");
		}
		for (int i = 0; i < members.length; i++) {
			final File addFile = members[i];
			try {
				if (!CodeHandler.addAddtionalFile(addFile)) {
					return false;
				}
			} catch (CoreException | IOException e) {
				e.printStackTrace();
			}
		}
		return true;
	}
	
	public static boolean addAddtionalFile(File fileToBeAdded) throws CoreException, IOException {
		final IFolder libFolder = dProject.getFolder(Constants.pathsForLibrariesInDevProject);
		if (!libFolder.exists()) {
			libFolder.create(true, true, null);
		}

		final Path memberPath = fileToBeAdded.toPath();
		Files.copy(memberPath, new File(dProject.getProjectPath() + Constants.outerFileSeparator + Constants.pathsForLibrariesInDevProject + Constants.outerFileSeparator + memberPath.getFileName()).toPath(),
				StandardCopyOption.REPLACE_EXISTING);
		final String filePath = fileToBeAdded.toString();
		final String cutPath = filePath.substring(filePath.lastIndexOf(Constants.outerFileSeparator));
		if (Constants.JAR.equals(cutPath.substring(cutPath.indexOf(".")))) {
			if (!dProject.addJar(Constants.pathsForLibrariesInDevProject + Constants.outerFileSeparator + fileToBeAdded.getName())) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * This method deletes a JavaProject from the Workspace/hard drive
	 * 
	 * @param project Java project that will be deleted
	 * @throws CoreException
	 * @throws InterruptedException
	 */
	private static void deleteProject(final IProject project) throws CoreException {
		if(project.exists()) {
			LOGGER.info("Deleting existing project.");
			project.delete(true, true, null);
			LOGGER.info("Finished deletion.");
		}
	}
	
	public static void cleanUpProject() throws CoreException {
		dProject.refresh();
		final ICompilationUnit[] units = dProject.getPackagesOfProject("jca").getCompilationUnits();

		if (units.length > 0 && units[0].getResource().getType() == IResource.FILE) {
			IFile genClass = (IFile) units[0].getResource();
			IDE.openEditor(UIUtils.getCurrentlyOpenPage(), genClass);
			IEditorPart editor = UIUtils.getCurrentlyOpenPage().getActiveEditor();
			final FormatAllAction faa = new FormatAllAction(editor.getSite());
			faa.runOnMultiple(units);
		} else {
			LOGGER.info("No files found.");
		}
	}
}
