package dev.sigstore.plugin;

public interface SigstoreProcessor
{
    enum Type {
        PGP("pgp"),
        X_509("x509"),
        SSH("ssh");
        private final String value;
        Type(String value) {
            this.value = value;
        }
    }

    SigstoreResult process( SigstoreRequest request ) throws Exception;
}
