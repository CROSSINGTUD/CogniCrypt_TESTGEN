package de.cognicrypt.testgenerator.test;

import java.io.File;
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
import org.eclipse.jdt.core.IPackageFragment;
import org.eclipse.jdt.core.IPackageFragmentRoot;
import org.eclipse.jdt.core.JavaCore;
import org.eclipse.jdt.core.JavaModelException;
import org.eclipse.jdt.launching.IVMInstall;
import org.eclipse.jdt.launching.JavaRuntime;
import org.eclipse.jdt.launching.LibraryLocation;
import org.eclipse.jdt.ui.actions.FormatAllAction;
import org.eclipse.ui.IEditorPart;
import org.eclipse.ui.ide.IDE;

import com.google.common.collect.Lists;

import de.cognicrypt.core.Constants;
import de.cognicrypt.testgenerator.Activator;
import de.cognicrypt.testgenerator.utils.Utils;
import de.cognicrypt.utils.DeveloperProject;
import de.cognicrypt.utils.UIUtils;

public class TestProject {
	
	private static final Logger LOGGER = Logger.getLogger(TestProject.class.getName());

	private IJavaProject jProject;
	private DeveloperProject dProject;
	public TestProject(String name) {
		try {
			jProject = createJavaProject(name);
		} catch (CoreException e) {
			Activator.getDefault().logError(e, "Failed to create test project.");
		}
		dProject = new DeveloperProject(jProject.getProject());
		addAdditionalFiles("lib");
	}
	
	private boolean addAdditionalFiles(final String source) {
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
				if (!addAddtionalFile(addFile)) {
					return false;
				}
			} catch (CoreException | IOException e) {
				e.printStackTrace();
			}
		}
		return true;
	}

	private boolean addAddtionalFile(File fileToBeAdded) throws CoreException, IOException {
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

	public IJavaProject getProject() {
		return jProject;
	}
	
	/**
	 * This method creates a package with a java class into a JavaProject <<<<<<< HEAD
	 * 
	 * @param packageName package in which the new Java class will be generated
	 * @param className name of the new Java class
	 * @throws JavaModelException
	 */
	public IResource generateTestClass(final String className) throws JavaModelException {

		String testClassName = className + "Test";
		final IPackageFragment pack = jProject.getPackageFragmentRoot(jProject.getProject().getFolder("src")).createPackageFragment("jca", false, null);
		final String source = "public class " + testClassName + " {\n\n}\n";
		final StringBuffer buffer = new StringBuffer();
		buffer.append("package " + pack.getElementName() + ";\r\n\r\n");
		buffer.append(source);
		ICompilationUnit unit = pack.createCompilationUnit(testClassName + ".java", buffer.toString(), false, null);
		return unit.getUnderlyingResource();
	}
	
	/**
	 * This method creates a empty JavaProject in the current workspace
	 * 
	 * @param projectName for the JavaProject
	 * @return new created JavaProject
	 * @throws CoreException
	 */
	private IJavaProject createJavaProject(final String projectName) throws CoreException {

		LOGGER.info("Creating " + projectName + " project.");
		
		final IWorkspaceRoot workSpaceRoot = ResourcesPlugin.getWorkspace().getRoot();
		deleteProject(workSpaceRoot.getProject(projectName));

		final IProject project = workSpaceRoot.getProject(projectName);
		project.create(null);
		project.open(null);

		final IProjectDescription description = project.getDescription();
		description.setNatureIds(new String[] {JavaCore.NATURE_ID});
		project.setDescription(description, null);

		final IJavaProject javaProject = JavaCore.create(project);

		final IFolder binFolder = project.getFolder("bin");
		binFolder.create(false, true, null);
		javaProject.setOutputLocation(binFolder.getFullPath(), null);

		final List<IClasspathEntry> entries = Lists.newArrayList();
		final IVMInstall vmInstall = JavaRuntime.getDefaultVMInstall();
		final LibraryLocation[] locations = JavaRuntime.getLibraryLocations(vmInstall);
		for (final LibraryLocation element : locations) {
			entries.add(JavaCore.newLibraryEntry(element.getSystemLibraryPath(), null, null));
		}
		// add libs to project class path
		javaProject.setRawClasspath(entries.toArray(new IClasspathEntry[entries.size()]), null);

		final IFolder sourceFolder = project.getFolder("src");
		sourceFolder.create(false, true, null);

		final IPackageFragmentRoot packageRoot = javaProject.getPackageFragmentRoot(sourceFolder);
		final IClasspathEntry[] oldEntries = javaProject.getRawClasspath();
		final IClasspathEntry[] newEntries = new IClasspathEntry[oldEntries.length + 1];
		System.arraycopy(oldEntries, 0, newEntries, 0, oldEntries.length);
		newEntries[oldEntries.length] = JavaCore.newSourceEntry(packageRoot.getPath());
		javaProject.setRawClasspath(newEntries, null);
		
		LOGGER.info("Finished creating " + projectName + " project.");

		return javaProject;
	}
	
	/**
	 * This method deletes a JavaProject from the Workspace/hard drive
	 * 
	 * @param project Java project that will be deleted
	 * @throws CoreException
	 * @throws InterruptedException
	 */
	private void deleteProject(final IProject project) throws CoreException {
		if(project.exists()) {
			LOGGER.info("Deleting existing project.");
			project.delete(true, true, null);
			LOGGER.info("Finished deletion.");
		}
	}
	
	public void cleanUpProject() throws CoreException {
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

	public String getProjectPath() {
		return dProject.getProjectPath();
	}

	public String getSourcePath() {
		try {
			return dProject.getSourcePath();
		} catch (CoreException e) {
			e.printStackTrace();
		}
		return null;
	}
}
