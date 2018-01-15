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
package com.grepplabs.kafka.security.sasl.authenticator;

import com.grepplabs.kafka.security.sasl.plain.PlainLoginModule;
import org.apache.kafka.common.config.types.Password;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestJaasConfig extends Configuration {

    public static final String LOGIN_CONTEXT_CLIENT = "KafkaClient";
    public static final String LOGIN_CONTEXT_SERVER = "KafkaServer";

    static final String USERNAME = "myuser";
    static final String PASSWORD = "mypassword";

    private Map<String, AppConfigurationEntry[]> entryMap = new HashMap<>();

    public static TestJaasConfig createConfiguration(String clientMechanism, List<String> serverMechanisms) {
        TestJaasConfig config = new TestJaasConfig();
        config.createOrUpdateEntry(LOGIN_CONTEXT_CLIENT, loginModule(clientMechanism), defaultClientOptions());
        for (String mechanism : serverMechanisms) {
            config.addEntry(LOGIN_CONTEXT_SERVER, loginModule(mechanism), defaultServerOptions(mechanism));
        }
        Configuration.setConfiguration(config);
        return config;
    }

    public static Password jaasConfigProperty(String mechanism, String username, String password) {
        return new Password(loginModule(mechanism) + " required username=" + username + " password=" + password + ";");
    }

    public void setClientOptions(String saslMechanism, String clientUsername, String clientPassword) {
        Map<String, Object> options = new HashMap<>();
        if (clientUsername != null)
            options.put("username", clientUsername);
        if (clientPassword != null)
            options.put("password", clientPassword);
        Class<?> loginModuleClass = PlainLoginModule.class;
        createOrUpdateEntry(LOGIN_CONTEXT_CLIENT, loginModuleClass.getName(), options);
    }

    public void createOrUpdateEntry(String name, String loginModule, Map<String, Object> options) {
        AppConfigurationEntry entry = new AppConfigurationEntry(loginModule, LoginModuleControlFlag.REQUIRED, options);
        entryMap.put(name, new AppConfigurationEntry[] {entry});
    }

    public void addEntry(String name, String loginModule, Map<String, Object> options) {
        AppConfigurationEntry entry = new AppConfigurationEntry(loginModule, LoginModuleControlFlag.REQUIRED, options);
        AppConfigurationEntry[] existing = entryMap.get(name);
        AppConfigurationEntry[] newEntries = existing == null ? new AppConfigurationEntry[1] : Arrays.copyOf(existing, existing.length + 1);
        newEntries[newEntries.length - 1] = entry;
        entryMap.put(name, newEntries);
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        return entryMap.get(name);
    }

    private static String loginModule(String mechanism) {
        String loginModule;
        switch (mechanism) {
            case "PLAIN":
                loginModule = PlainLoginModule.class.getName();
                break;
            default:
                throw new IllegalArgumentException("Unsupported mechanism " + mechanism);
        }
        return loginModule;
    }

    public static Map<String, Object> defaultClientOptions() {
        Map<String, Object> options = new HashMap<>();
        options.put("username", USERNAME);
        options.put("password", PASSWORD);
        return options;
    }

    public static Map<String, Object> defaultServerOptions(String mechanism) {
        Map<String, Object> options = new HashMap<>();
        switch (mechanism) {
            case "PLAIN":
            case "DIGEST-MD5":
                options.put("user_" + USERNAME, PASSWORD);
                break;
            default:
                throw new IllegalArgumentException("Unsupported mechanism " + mechanism);
        }
        return options;
    }
}

