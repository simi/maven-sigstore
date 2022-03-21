
package dev.sigstore.plugin;

import java.util.Map;

public abstract class SigstoreProcessorSupport implements SigstoreProcessor
{
    protected Map<String, Object> rekord( SigstoreRequest request, SigstoreResult result ) throws Exception {
        //return RekordGenerator.rekord(request, result);
        return HashedRekordGenerator.hashrekord(request, result);
    }
}
