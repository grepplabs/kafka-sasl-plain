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
import org.apache.kafka.common.network.ListenerName;
import org.apache.kafka.common.security.JaasContext;
import org.junit.Test;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.grepplabs.kafka.security.sasl.plain.PlainSaslServer.PlainSaslServerFactory.getListenerName;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;


public class JaasContextProviderTest extends AbstractJaasContextTest {

    @Test
    public void testConfigNoOptions() throws Exception {
        checkConfiguration("test.testConfigNoOptions", LoginModuleControlFlag.REQUIRED, new HashMap<String, Object>());
    }

    @Test
    public void testControlFlag() throws Exception {
        LoginModuleControlFlag[] controlFlags = new LoginModuleControlFlag[] {
                LoginModuleControlFlag.REQUIRED,
                LoginModuleControlFlag.REQUISITE,
                LoginModuleControlFlag.SUFFICIENT,
                LoginModuleControlFlag.OPTIONAL
        };
        Map<String, Object> options = new HashMap<>();
        options.put("propName", "propValue");
        for (LoginModuleControlFlag controlFlag : controlFlags) {
            checkConfiguration("test.testControlFlag", controlFlag, options);
        }
    }

    @Test
    public void testSingleOption() throws Exception {

        Map<String, Object> options = new HashMap<>();
        options.put("propName", "propValue");
        checkConfiguration("test.testSingleOption", LoginModuleControlFlag.REQUISITE, options);
    }

    @Test
    public void testMultipleOptions() throws Exception {
        Map<String, Object> options = new HashMap<>();
        for (int i = 0; i < 10; i++)
            options.put("propName" + i, "propValue" + i);
        checkConfiguration("test.testMultipleOptions", LoginModuleControlFlag.SUFFICIENT, options);
    }

    @Test
    public void testQuotedOptionValue() throws Exception {
        Map<String, Object> options = new HashMap<>();
        options.put("propName", "prop value");
        options.put("propName2", "value1 = 1, value2 = 2");
        String config = String.format("test.testQuotedOptionValue required propName=\"%s\" propName2=\"%s\";", options.get("propName"), options.get("propName2"));
        checkConfiguration(config, "test.testQuotedOptionValue", LoginModuleControlFlag.REQUIRED, options);
    }

    @Test
    public void testQuotedOptionName() throws Exception {
        Map<String, Object> options = new HashMap<>();
        options.put("prop name", "propValue");
        String config = "test.testQuotedOptionName required \"prop name\"=propValue;";
        checkConfiguration(config, "test.testQuotedOptionName", LoginModuleControlFlag.REQUIRED, options);
    }

    @Test
    public void testMissingLoginModule() throws Exception {
        checkInvalidConfiguration("  required option1=value1;");
    }

    @Test
    public void testMissingControlFlag() throws Exception {
        checkInvalidConfiguration("test.loginModule option1=value1;");
    }

    @Test
    public void testMissingOptionValue() throws Exception {
        checkInvalidConfiguration("loginModule required option1;");
    }

    @Test
    public void testMissingSemicolon() throws Exception {
        checkInvalidConfiguration("test.testMissingSemicolon required option1=value1");
    }

    @Test
    public void testNumericOptionWithoutQuotes() throws Exception {
        checkInvalidConfiguration("test.testNumericOptionWithoutQuotes required option1=3;");
    }

    @Test
    public void testNumericOptionWithQuotes() throws Exception {
        Map<String, Object> options = new HashMap<>();
        options.put("option1", "3");
        String config = "test.testNumericOptionWithQuotes required option1=\"3\";";
        checkConfiguration(config, "test.testNumericOptionWithQuotes", LoginModuleControlFlag.REQUIRED, options);
    }

    @Test
    public void testLoadForServerWithListenerNameOverride() throws IOException {
        writeConfiguration(Arrays.asList(
                "KafkaServer { test.LoginModuleDefault required; };",
                "plaintext.KafkaServer { test.LoginModuleOverride requisite; };"
        ));
        JaasContext context = JaasContext.load(JaasContext.Type.SERVER, new ListenerName("plaintext"),
                Collections.<String, Object>emptyMap());
        assertEquals("plaintext.KafkaServer", context.name());
        assertEquals(JaasContext.Type.SERVER, context.type());
        assertEquals(1, context.configurationEntries().size());
        checkEntry(context.configurationEntries().get(0), "test.LoginModuleOverride",
                LoginModuleControlFlag.REQUISITE, Collections.<String, Object>emptyMap());
    }

    @Test
    public void testLoadForServerWithListenerNameAndFallback() throws IOException {
        writeConfiguration(Arrays.asList(
                "KafkaServer { test.LoginModule required; };",
                "other.KafkaServer { test.LoginModuleOther requisite; };"
        ));
        JaasContext context = JaasContext.load(JaasContext.Type.SERVER, new ListenerName("plaintext"),
                Collections.<String, Object>emptyMap());
        assertEquals("KafkaServer", context.name());
        assertEquals(JaasContext.Type.SERVER, context.type());
        assertEquals(1, context.configurationEntries().size());
        checkEntry(context.configurationEntries().get(0), "test.LoginModule", LoginModuleControlFlag.REQUIRED,
                Collections.<String, Object>emptyMap());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testListenerNameShouldNotBeNullForSERVER() {
        new PlainSaslServer.JaasContextProvider(JaasContext.Type.SERVER, null, Collections.<String, Object>emptyMap());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testListenerNameShouldBeNullForCLIENT() {
        new PlainSaslServer.JaasContextProvider(JaasContext.Type.CLIENT, new ListenerName("client"), Collections.<String, Object>emptyMap());
    }

    @Test
    public void testGetListenerName() {
        ListenerName listenerName;

        listenerName = getListenerName(JaasContext.Type.CLIENT, "my-client", "SASL_SSL");
        assertNull(listenerName);

        listenerName = getListenerName(JaasContext.Type.SERVER, "my-client.KafkaServer", "SASL_SSL");
        assertNotNull(listenerName);
        assertEquals("my-client", listenerName.value());

        listenerName = getListenerName(JaasContext.Type.SERVER, "KafkaServer", "SASL_SSL");
        assertNotNull(listenerName);
        assertEquals("SASL_SSL", listenerName.value());
    }

    /**
     * ListenerName can only be used with Type.SERVER.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testLoadForClientWithListenerName() {
        JaasContext.load(JaasContext.Type.CLIENT, new ListenerName("foo"),
                Collections.<String, Object>emptyMap());
    }


    private void checkInvalidConfiguration(String jaasConfigProp) throws IOException {
        try {
            writeConfiguration(TestJaasConfig.LOGIN_CONTEXT_SERVER, jaasConfigProp);
            AppConfigurationEntry entry = configurationEntry(JaasContext.Type.SERVER, null);
            fail("Invalid JAAS configuration file didn't throw exception, entry=" + entry);
        } catch (SecurityException e) {
            // Expected exception
        }
        try {
            AppConfigurationEntry entry = configurationEntry(JaasContext.Type.CLIENT, jaasConfigProp);
            fail("Invalid JAAS configuration property didn't throw exception, entry=" + entry);
        } catch (IllegalArgumentException e) {
            // Expected exception
        }
    }
}
