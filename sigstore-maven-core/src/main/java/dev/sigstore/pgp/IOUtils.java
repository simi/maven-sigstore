package dev.sigstore.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class IOUtils {

  private static final int BUFFER_SIZE = 4096;

  public static void copy(InputStream inputStream, final OutputStream outputStream, byte[] buffer, final StreamHandler addtionalHandling) throws IOException {
    process(inputStream, (buffer1, offset, length) -> {
      outputStream.write(buffer1, offset, length);
      if (addtionalHandling != null) {
        addtionalHandling.handleStreamBuffer(buffer1, offset, length);
      }
    }, buffer);
  }

  public static void process(InputStream inputStream, StreamHandler handler) throws IOException {
    process(inputStream, handler, new byte[BUFFER_SIZE]);
  }

  public static void process(InputStream inputStream, StreamHandler handler, byte[] buffer) throws IOException {
    int read;
    while ((read = inputStream.read(buffer)) != -1) {
      handler.handleStreamBuffer(buffer, 0, read);
    }
  }

  public interface StreamHandler {

    void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException;

  }

}
