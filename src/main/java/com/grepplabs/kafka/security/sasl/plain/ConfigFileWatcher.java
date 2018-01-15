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

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.concurrent.TimeUnit;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

public class ConfigFileWatcher implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(ConfigFileWatcher.class);

    private final ConfigFileChangeListener listener;
    private final File file;

    private volatile boolean stop;

    ConfigFileWatcher(final String filename, final ConfigFileChangeListener listener) {
        this.listener = listener;
        this.file = new File(filename);
    }

    @Override
    public void run() {
        final Path path = file.toPath().getParent();
        log.info("Starting watching file {}", file);
        try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
            path.register(watchService, ENTRY_CREATE, ENTRY_MODIFY);

            long lastModifiedTime = getLastModifiedTime();

            while (!stop) {
                WatchKey key;
                try {
                    key = watchService.poll(500, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    return;
                }
                if (key == null) {
                    continue;
                }

                for (WatchEvent<?> watchEvent : key.pollEvents()) {
                    final WatchEvent.Kind<?> kind = watchEvent.kind();
                    if (kind == StandardWatchEventKinds.OVERFLOW) {
                        continue;
                    }
                    @SuppressWarnings("unchecked") final WatchEvent<Path> watchEventPath = (WatchEvent<Path>) watchEvent;
                    final Path filename = watchEventPath.context();
                    log.debug("Change {} on file {}", kind, filename);

                    long newLastModifiedTime = getLastModifiedTime();
                    if (lastModifiedTime != newLastModifiedTime && newLastModifiedTime != 0L) {

                        lastModifiedTime = newLastModifiedTime;

                        listener.configFileChanged();
                    }
                }

                final boolean valid = key.reset();
                if (!valid) {
                    break;
                }
            }
        } catch (Throwable t) {
            log.error("Unexpected error while watching the file {} watcher ", file, t);
        } finally {
            log.info("File watcher will be stopped");
        }
    }

    private long getLastModifiedTime() {
        if (file.canRead()) {
            try {
                return Files.getLastModifiedTime(file.toPath()).toMillis();
            } catch (IOException e) {
                log.warn("Unexpected error while getting the file {} LastModifiedTime ", file, e);
            }
        }
        return 0L;
    }

    public void stop() {
        this.stop = true;
    }
}
