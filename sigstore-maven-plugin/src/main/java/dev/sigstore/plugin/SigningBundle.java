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

public class SigningBundle
{
    private final String extension;

    private final String classifier;

    private final File signature;

    public SigningBundle( String extension, File signature )
    {
        this( extension, signature, null );
    }

    public SigningBundle( String extension, File signature, String classifier )
    {
        this.extension = extension;
        this.classifier = classifier;
        this.signature = signature;
    }

    public String getExtension()
    {
        return extension;
    }

    public File getSignature()
    {
        return signature;
    }

    public String getClassifier()
    {
        return classifier;
    }
}