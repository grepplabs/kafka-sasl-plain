/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.grepplabs.kafka.security.sasl.plain;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;

/**
 * @see org.apache.kafka.common.security.plain.PlainSaslServerProvider
 */
public class PlainSaslServerProvider extends Provider {

    private static final Logger log = LoggerFactory.getLogger(PlainSaslServer.class);

    private static final long serialVersionUID = 1L;

    protected PlainSaslServerProvider() {
        super("SASL/PLAIN Server Provider.", 1.0, "Simple SASL/PLAIN Server Provider for Kafka with reloadable JAAS login configuration file.");
        super.put("SaslServerFactory." + PlainSaslServer.PLAIN_MECHANISM, PlainSaslServer.PlainSaslServerFactory.class.getName());
    }

    public static void initialize() {
        log.info("Init provider {}", PlainSaslServerProvider.class.getName());
        Security.addProvider(new PlainSaslServerProvider());
    }
}
