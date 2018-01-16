# Kafka SASL/PLAIN

Kafka authentication via SASL/PLAIN with reloadable JAAS login configuration file.

[![Build Status](https://travis-ci.org/grepplabs/kafka-sasl-plain.svg?branch=master)](https://travis-ci.org/grepplabs/kafka-sasl-plain)

PlainLoginModule based on [org.apache.kafka.common.security.plain.PlainLoginModule](https://sourcegraph.com/github.com/apache/kafka@heads/trunk/-/blob/clients/src/main/java/org/apache/kafka/common/security/plain/PlainLoginModule.java)
which watches and reloads JAAS configuration file.

## Usage

kafka_server_jaas.conf:

```
KafkaServer {
   com.grepplabs.kafka.security.sasl.plain.PlainLoginModule required
   username="admin"
   password="admin-secret"
   user_admin="admin-secret"
   user_alice="alice-secret";
};

```
