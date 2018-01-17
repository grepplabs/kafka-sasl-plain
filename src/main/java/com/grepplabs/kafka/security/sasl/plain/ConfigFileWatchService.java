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

import org.apache.kafka.common.security.JaasUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.Configuration;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicReference;

public class ConfigFileWatchService implements ConfigFileChangeListener {
    private static final Logger log = LoggerFactory.getLogger(ConfigFileWatchService.class);

    private final AtomicReference<Thread> watcherThread = new AtomicReference<>();

    private final Map<ConfigFileChangeListener, Boolean> listeners = Collections.synchronizedMap(new WeakHashMap<ConfigFileChangeListener, Boolean>());

    public void startWatcher() {
        Thread thread = watcherThread.get();
        if (thread == null ) {
            String jaasConfigFile = System.getProperty(JaasUtils.JAVA_LOGIN_CONFIG_PARAM);
            if (jaasConfigFile != null && !jaasConfigFile.isEmpty()) {
                thread = new Thread(new ConfigFileWatcher(jaasConfigFile, this), "jaas-config-file-watcher");
                if (watcherThread.compareAndSet(null, thread)) {
                    thread.start();
                }
            } else {
                log.debug("Parameter {} is not set. ConfigFileWatcher will not be started.", JaasUtils.JAVA_LOGIN_CONFIG_PARAM);
            }
        }
    }

    public void stopWatcher() {
        Thread thread = watcherThread.get();
        if (thread != null ) {
            if (watcherThread.compareAndSet(thread, null)) {
                thread.interrupt();
            }
        }
    }

    @Override
    public void configFileChanged() {
        try {
            log.info("Auth configuration will be refreshed");

            // refresh configuration to reload the data
            synchronized (Configuration.class) {
                Configuration.getConfiguration().refresh();
            }
            notifyChangeListeners();
        } catch (Throwable t) {
            log.warn("Auth configuration change failed {}", t.toString());
        }
    }

    public void addListener(ConfigFileChangeListener listener) {
        this.listeners.put(listener, Boolean.TRUE);
    }

    public void removeListener(ConfigFileChangeListener listener) {
        this.listeners.remove(listener);
    }

    /** See also {@link java.util.Collections#synchronizedMap}. */
    private void notifyChangeListeners() {
        Set<ConfigFileChangeListener> keys = listeners.keySet();
        synchronized (listeners) {
            log.info("Notify {} listeners ", keys.size());
            for (ConfigFileChangeListener key : keys) {
                key.configFileChanged();
            }
        }
    }

    int getListenersCount() {
        return listeners.size();
    }
}
