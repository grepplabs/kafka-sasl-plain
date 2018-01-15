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

import com.grepplabs.kafka.security.sasl.authenticator.TestJaasConfig;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.common.network.ListenerName;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.JaasUtils;
import org.junit.After;
import org.junit.Before;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;


public class AbstractJaasContextTest {
    private File jaasConfigFile;

    @Before
    public void setUp() throws IOException {
        jaasConfigFile = File.createTempFile("jaas", ".conf");
        jaasConfigFile.deleteOnExit();
        System.setProperty(JaasUtils.JAVA_LOGIN_CONFIG_PARAM, jaasConfigFile.toString());
        Configuration.setConfiguration(null);
    }

    @After
    public void tearDown() throws Exception {
        Files.delete(jaasConfigFile.toPath());
    }

    void writeConfiguration(String contextName, String jaasConfigProp) throws IOException {
        writeConfiguration(contextName, jaasConfigProp, true);
    }
    void writeConfiguration(String contextName, String jaasConfigProp, boolean reset) throws IOException {
        List<String> lines = Arrays.asList(contextName + " { ", jaasConfigProp, "};");
        writeConfiguration(lines, reset);
    }

    void writeConfiguration(List<String> lines) throws IOException {
        writeConfiguration(lines, true);
    }

    private void writeConfiguration(List<String> lines, boolean reset) throws IOException {
        Files.write(jaasConfigFile.toPath(), lines, StandardCharsets.UTF_8);
        if (reset) {
            Configuration.setConfiguration(null);
        }
    }

    AppConfigurationEntry configurationEntry(JaasContext.Type contextType, String jaasConfigProp) {
        Map<String, Object> configs = new HashMap<>();
        if (jaasConfigProp != null)
            configs.put(SaslConfigs.SASL_JAAS_CONFIG, new Password(jaasConfigProp));

        final ListenerName listenerName = PlainSaslServer.PlainSaslServerFactory.getListenerName(contextType, contextType.name(), contextType.name());
        final PlainSaslServer.JaasContextProvider provider = new PlainSaslServer.JaasContextProvider(contextType, listenerName, configs);
        List<AppConfigurationEntry> entries = provider.get().configurationEntries();
        assertEquals(1, entries.size());
        return entries.get(0);
    }

    private String controlFlag(LoginModuleControlFlag loginModuleControlFlag) {
        // LoginModuleControlFlag.toString() has format "LoginModuleControlFlag: flag"
        String[] tokens = loginModuleControlFlag.toString().split(" ");
        return tokens[tokens.length - 1];
    }

    String jaasConfigProp(String loginModule, LoginModuleControlFlag controlFlag, Map<String, Object> options) {
        StringBuilder builder = new StringBuilder();
        builder.append(loginModule);
        builder.append(' ');
        builder.append(controlFlag(controlFlag));
        for (Map.Entry<String, Object> entry : options.entrySet()) {
            builder.append(' ');
            builder.append(entry.getKey());
            builder.append('=');
            builder.append(entry.getValue());
        }
        builder.append(';');
        return builder.toString();
    }


    void checkConfiguration(String loginModule, LoginModuleControlFlag controlFlag, Map<String, Object> options) throws Exception {
        String jaasConfigProp = jaasConfigProp(loginModule, controlFlag, options);
        checkConfiguration(jaasConfigProp, loginModule, controlFlag, options);
    }

    void checkEntry(AppConfigurationEntry entry, String loginModule, LoginModuleControlFlag controlFlag, Map<String, ?> options) {
        assertEquals(loginModule, entry.getLoginModuleName());
        assertEquals(controlFlag, entry.getControlFlag());
        assertEquals(options, entry.getOptions());
    }

    void checkConfiguration(String jaasConfigProp, String loginModule, LoginModuleControlFlag controlFlag, Map<String, Object> options) throws Exception {
        AppConfigurationEntry dynamicEntry = configurationEntry(JaasContext.Type.CLIENT, jaasConfigProp);
        checkEntry(dynamicEntry, loginModule, controlFlag, options);
        assertNull("Static configuration updated", Configuration.getConfiguration().getAppConfigurationEntry(JaasContext.Type.CLIENT.name()));

        writeConfiguration(TestJaasConfig.LOGIN_CONTEXT_SERVER, jaasConfigProp);
        AppConfigurationEntry staticEntry = configurationEntry(JaasContext.Type.SERVER, null);
        checkEntry(staticEntry, loginModule, controlFlag, options);
    }
}
