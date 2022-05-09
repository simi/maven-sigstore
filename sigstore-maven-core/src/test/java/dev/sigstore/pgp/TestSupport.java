package dev.sigstore.pgp;

import java.io.File;
import org.junit.Before;

public class TestSupport {

  String basedir;
  File files;

  @Before
  public void setUp() {
    basedir = System.getProperty("basedir", new File("").getAbsolutePath());
    files = new File(basedir, "target/files");
  }

  public File files(String name) {
    File workingDirectory = new File(files, name);
    if (!workingDirectory.exists()) {
      workingDirectory.mkdirs();
    }
    return workingDirectory;
  }
}
