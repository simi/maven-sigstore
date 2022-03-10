package dev.sigstore.plugin;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import javax.annotation.Nullable;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.util.Map;

import org.apache.maven.sigstore.model.hashedrekord.Hashedrekord;
import org.apache.maven.sigstore.model.rekord.Rekord;
import org.immutables.value.Value;

/**
 * Sign
 */
@Value.Immutable
public abstract class SigstoreResult
{
    @Nullable
    public abstract String emailAddress();

    @Nullable
    public abstract String signedEmailAddress();

    @Nullable
    public abstract String rawIdToken();

    @Nullable
    public abstract KeyPair keyPair();

    @Nullable
    public abstract String artifactSignatureContent(); // b64

    @Nullable
    public abstract String artifactSigningCertContent();

    @Nullable
    public abstract CertPath signingCert();

    @Nullable
    public abstract String publicKeyContent();

    @Nullable
    public abstract Path publicKeyPath();

    @Nullable
    public abstract Map<String, Object> rekorRecord();

    @Nullable
    public abstract String rekorEntryUrl();
}