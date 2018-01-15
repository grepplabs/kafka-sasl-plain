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
import org.apache.kafka.common.security.authenticator.SaslServerCallbackHandler;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;

public class PlainSaslServerFactoryTest extends AbstractJaasContextTest {

    @Test
    public void testReloadConfig() throws Exception {

        final Map<String, Object> options = new HashMap<>();
        options.put("username", "\"admin\"");
        options.put("password", "\"admin123456\"");
        options.put("user_admin", "\"admin123456\"");
        options.put("user_alice", "\"pass12345\"");
        writeStaticConfiguration(PlainLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUISITE, options);

        PlainSaslServer.PlainSaslServerFactory factory = new PlainSaslServer.PlainSaslServerFactory();
        JaasContext jaasContext = JaasContext.load(JaasContext.Type.SERVER, new ListenerName("my-listener"), Collections.<String, Object>emptyMap());
        final SaslServer server = factory.createSaslServer(PlainSaslServer.PLAIN_MECHANISM, "SASL_SSL", "my-broker", Collections.<String, Object>emptyMap(), new SaslServerCallbackHandler(jaasContext, null));
        server.evaluateResponse(saslMessage("alice", "alice", "pass12345"));

        try {
            server.evaluateResponse(saslMessage("bob", "bob", "pass6789"));
            Assert.fail("User is not configured yet");
        } catch (SaslException ignore) {};

        options.put("user_bob", "\"pass6789\"");

        await().atMost(6, TimeUnit.SECONDS).pollInterval(500, TimeUnit.MILLISECONDS). until(new Callable<Boolean>() {
            @Override
            public Boolean call() {
                try {
                    writeStaticConfiguration(PlainLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUISITE, options);
                    server.evaluateResponse(saslMessage("bob", "bob", "pass6789"));
                    return true;
                } catch (Exception ignore) {
                    return false;
                }
            }
        });

        server.dispose();
        PlainSaslServer.CONFIG_FILE_WATCH_SERVICE.stopWatcher();
    }

    @Test
    public void testReloadOldConfigWithKafkaModuleName() throws Exception {
        final Map<String, Object> options = new HashMap<>();
        options.put("username", "\"admin\"");
        options.put("password", "\"admin123456\"");
        options.put("user_admin", "\"admin123456\"");
        options.put("user_alice", "\"pass12345\"");
        options.put("user_bob", "\"pass6789\"");
        writeStaticConfiguration(PlainLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUISITE, options);

        PlainSaslServer.PlainSaslServerFactory factory = new PlainSaslServer.PlainSaslServerFactory();
        JaasContext jaasContext = JaasContext.load(JaasContext.Type.SERVER, new ListenerName("my-listener"), Collections.<String, Object>emptyMap());
        final SaslServer server = factory.createSaslServer(PlainSaslServer.PLAIN_MECHANISM, "SASL_SSL", "my-broker", Collections.<String, Object>emptyMap(), new SaslServerCallbackHandler(jaasContext, null));
        server.evaluateResponse(saslMessage("alice", "alice", "pass12345"));

        options.remove("user_bob");

        await().atMost(6, TimeUnit.SECONDS).pollInterval(500, TimeUnit.MILLISECONDS). until(new Callable<Boolean>() {
            @Override
            public Boolean call() {
                try {
                    writeStaticConfiguration(org.apache.kafka.common.security.plain.PlainLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUISITE, options);
                    server.evaluateResponse(saslMessage("bob", "bob", "pass6789"));
                    return false;
                } catch (Exception ignore) {
                    return true;
                }
            }
        });
        server.evaluateResponse(saslMessage("alice", "alice", "pass12345"));

        server.dispose();
        PlainSaslServer.CONFIG_FILE_WATCH_SERVICE.stopWatcher();
    }

    private void writeStaticConfiguration(String loginModule, AppConfigurationEntry.LoginModuleControlFlag controlFlag, Map<String, Object> options) throws Exception {
        String jaasConfigProp = jaasConfigProp(loginModule, controlFlag, options);
        writeConfiguration(TestJaasConfig.LOGIN_CONTEXT_SERVER, jaasConfigProp, false);
    }


    private byte[] saslMessage(String authorizationId, String userName, String password) {
        String nul = "\u0000";
        String message = String.format("%s%s%s%s%s", authorizationId, nul, userName, nul, password);
        return message.getBytes(StandardCharsets.UTF_8);
    }
}
