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

import java.io.File;
import java.net.URL;

import org.immutables.value.Value;

/**
 * Sign
 */
@Value.Immutable
public abstract class SigstoreRequest
{
    public abstract File artifact();

    public abstract File outputSignedJar();

    public abstract File outputSigningCert();

    public abstract String signerName();

    public abstract String signingAlgorithm();

    public abstract String signingAlgorithmSpec();

    public abstract boolean sslVerfication();

    public abstract URL fulcioInstanceURL();

    public abstract boolean oidcDeviceCodeFlow();

    public abstract String oidcClientID();

    public abstract URL oidcAuthURL();

    public abstract URL oidcTokenURL();

    public abstract URL oidcDeviceCodeURL();

    public abstract URL rekorInstanceURL();

    public abstract String emailAddress();

    public abstract URL tsaURL();
}