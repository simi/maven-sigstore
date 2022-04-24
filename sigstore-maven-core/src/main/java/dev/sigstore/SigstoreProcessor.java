package dev.sigstore;

public interface SigstoreProcessor {

  SigstoreResult process(SigstoreRequest request) throws Exception;
}
