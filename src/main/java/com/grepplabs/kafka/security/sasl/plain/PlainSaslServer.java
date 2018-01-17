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

import org.apache.kafka.common.network.ListenerName;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.authenticator.SaslServerCallbackHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Simple SaslServer implementation for SASL/PLAIN. In order to make this implementation
 * fully pluggable, authentication of username/password is fully contained within the
 * server implementation.
 * <p>
 * Valid users with passwords are specified in the Jaas configuration file. Each user
 * is specified with user &lt;username&gt; as key and &lt;password&gt; as value. This is consistent
 * with Zookeeper Digest-MD5 implementation.
 * <p>
 * To avoid storing clear passwords on disk or to integrate with external authentication
 * servers in production systems, this module can be replaced with a different implementation.
 *
 * @see org.apache.kafka.common.security.plain.PlainSaslServer
 */
public class PlainSaslServer implements SaslServer {
    private static final Logger log = LoggerFactory.getLogger(PlainSaslServer.class);

    public static final String PLAIN_MECHANISM = "PLAIN";
    private static final String JAAS_USER_PREFIX = "user_";

    final static ConfigFileWatchService CONFIG_FILE_WATCH_SERVICE = new ConfigFileWatchService();

    private final JaasContextProvider jaasContextProvider;

    private boolean complete;
    private String authorizationId;

    PlainSaslServer(JaasContextProvider jaasContextProvider) {
        this.jaasContextProvider = jaasContextProvider;
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        /*
         * Message format (from https://tools.ietf.org/html/rfc4616):
         *
         * message   = [authzid] UTF8NUL authcid UTF8NUL passwd
         * authcid   = 1*SAFE ; MUST accept up to 255 octets
         * authzid   = 1*SAFE ; MUST accept up to 255 octets
         * passwd    = 1*SAFE ; MUST accept up to 255 octets
         * UTF8NUL   = %x00 ; UTF-8 encoded NUL character
         *
         * SAFE      = UTF1 / UTF2 / UTF3 / UTF4
         *                ;; any UTF-8 encoded Unicode character except NUL
         */

        String[] tokens;
        try {
            tokens = new String(response, "UTF-8").split("\u0000");
        } catch (UnsupportedEncodingException e) {
            throw new SaslException("UTF-8 encoding not supported", e);
        }
        if (tokens.length != 3)
            throw new SaslException("Invalid SASL/PLAIN response: expected 3 tokens, got " + tokens.length);
        String authorizationIdFromClient = tokens[0];
        String username = tokens[1];
        String password = tokens[2];

        if (username.isEmpty()) {
            throw new SaslException("Authentication failed: username not specified");
        }
        if (password.isEmpty()) {
            throw new SaslException("Authentication failed: password not specified");
        }

        String expectedPassword = jaasContextProvider.get().configEntryOption(JAAS_USER_PREFIX + username,
                PlainLoginModule.class.getName());

        if (expectedPassword == null || expectedPassword.isEmpty()) {
            // Fallback to old module name.
            expectedPassword = jaasContextProvider.get().configEntryOption(JAAS_USER_PREFIX + username,
                    org.apache.kafka.common.security.plain.PlainLoginModule.class.getName());
        }

        if (!password.equals(expectedPassword)) {
            if (expectedPassword == null || expectedPassword.isEmpty()) {
                log.info("Authentication failed: Invalid username {}", username);
            } else {
                log.info("Authentication failed: Invalid password for username {}", username);
            }
            throw new SaslException("Authentication failed: Invalid username or password");
        }

        if (!authorizationIdFromClient.isEmpty() && !authorizationIdFromClient.equals(username)) {
            throw new SaslException("Authentication failed: Client requested an authorization id that is different from username");
        }
        this.authorizationId = username;

        complete = true;
        return new byte[0];
    }

    @Override
    public String getAuthorizationID() {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return authorizationId;
    }

    @Override
    public String getMechanismName() {
        return PLAIN_MECHANISM;
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return null;
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return Arrays.copyOfRange(incoming, offset, offset + len);
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return Arrays.copyOfRange(outgoing, offset, offset + len);
    }

    @Override
    public void dispose() throws SaslException {
        log.debug("Disposing SaslServer");
        jaasContextProvider.dispose();
    }

    public static class PlainSaslServerFactory implements SaslServerFactory {

        static ListenerName getListenerName(JaasContext.Type contextType, String contextName, String defaultListenerName) {
            if (contextType == JaasContext.Type.CLIENT) {
                return null;
            } else {
                String name = "";
                int index = contextName.lastIndexOf(".KafkaServer");
                if (index != -1) {
                    name = contextName.substring(0, index);
                }
                return name.isEmpty() ? new ListenerName(defaultListenerName) : new ListenerName(name);
            }
        }

        @Override
        public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh)
                throws SaslException {

            log.debug("Creating SaslServer: mechanism {}, protocol {}, serverName {} ms", mechanism, protocol, serverName);

            if (!PLAIN_MECHANISM.equals(mechanism))
                throw new SaslException(String.format("Mechanism \'%s\' is not supported. Only PLAIN is supported.", mechanism));

            if (!(cbh instanceof SaslServerCallbackHandler))
                throw new SaslException("CallbackHandler must be of type SaslServerCallbackHandler, but it is: " + cbh.getClass());

            final JaasContext oldJaasContext = ((SaslServerCallbackHandler) cbh).jaasContext();
            final JaasContextProvider jaasContextProvider = new JaasContextProvider(oldJaasContext.type(), getListenerName(oldJaasContext.type(), oldJaasContext.name(), protocol), props);
            jaasContextProvider.init();
            return new PlainSaslServer(jaasContextProvider);
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> props) {
            if (props == null) return new String[]{PLAIN_MECHANISM};
            String noPlainText = (String) props.get(Sasl.POLICY_NOPLAINTEXT);
            if ("true".equals(noPlainText))
                return new String[]{};
            else
                return new String[]{PLAIN_MECHANISM};
        }
    }

    public static class JaasContextProvider implements ConfigFileChangeListener{
        private static final Logger log = LoggerFactory.getLogger(JaasContextProvider.class);

        private final JaasContext.Type contextType;
        private final ListenerName listenerName;
        private final Map<String, ?> configs;

        private volatile boolean running;

        private final AtomicReference<JaasContext> jaasContextRef;

        JaasContextProvider(JaasContext.Type contextType, ListenerName listenerName, Map<String, ?> configs) {
            this.contextType = contextType;
            this.listenerName = listenerName;
            this.configs = configs;
            this.jaasContextRef = new AtomicReference<>(JaasContext.load(contextType, listenerName, configs));
        }

        JaasContextProvider(JaasContext jaasContext) {
            this.contextType = null;
            this.listenerName = null;
            this.configs = Collections.emptyMap();
            this.jaasContextRef = new AtomicReference<>(jaasContext);
        }

        JaasContext get() {
            return jaasContextRef.get();
        }

        void init() {
            running = true;
            CONFIG_FILE_WATCH_SERVICE.addListener(this);
            CONFIG_FILE_WATCH_SERVICE.startWatcher();
        }

        void dispose() {
            running = false;
            CONFIG_FILE_WATCH_SERVICE.removeListener(this);
        }

        @Override
        public void configFileChanged() {
            if (running) {
                try {
                    log.debug("JaasContext will be reloaded");
                    JaasContext newContext = JaasContext.load(contextType, listenerName, configs);
                    jaasContextRef.set(newContext);
                } catch (Exception e) {
                    log.warn("JaasContext reload failed {}", e.getMessage());
                }
            }
        }
    }
}
