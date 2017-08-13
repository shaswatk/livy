/*
 * Licensed to Cloudera, Inc. under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  Cloudera, Inc. licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudera.livy.server.metrics;

import com.cloudera.livy.LivyConf;

import java.lang.reflect.Constructor;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.health.HealthCheckRegistry;
import com.codahale.metrics.health.jvm.ThreadDeadlockHealthCheck;
import com.codahale.metrics.jvm.MemoryUsageGaugeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class is used to publish Livy metrics to any reporter host mentioned in config.
 * Metrics publishing is controlled by property. It is also registering JVM metrics to the metrics registry.
 */
public class MetricsPublisher {
  private static final Logger log = org.slf4j.LoggerFactory.getLogger(MetricsPublisher.class);
  private final MetricRegistry _metricRegistry;
  private final HealthCheckRegistry _healthCheckRegistry;
  private final String METRICS_REPORTER_NAME = "LivyServer";

  public MetricsPublisher(final MetricRegistry metricRegistry, final HealthCheckRegistry healthCheckRegistry) {
    this._metricRegistry = metricRegistry;
    this._healthCheckRegistry = healthCheckRegistry;
    registerJvmMetrics();
  }

  private void registerJvmMetrics() {
    this._metricRegistry.registerAll(new MemoryUsageGaugeSet());
    this._metricRegistry.registerAll(new CustomGarbageCollectorMetricSet());
    this._healthCheckRegistry.register("ThreadDeadlockHealthCheck", new ThreadDeadlockHealthCheck());
  }

  /**
   * reporting metrics to remote metrics collector.
   * Note: this method must be synchronized, since both web server and executor
   * will call it during initialization.
   */
  public synchronized void startReporting(final LivyConf livyConf) {
    final String metricsReporterClassName = livyConf.get(LivyConf.CUSTOM_METRICS_REPORTER_CLASS_NAME());
    final String metricsServerURL = livyConf.get(LivyConf.METRICS_REPORTER_SERVER_URL());
    if (metricsReporterClassName != null && metricsServerURL != null) {
      try {
        final Class metricsClass = Class.forName(metricsReporterClassName);
        final Constructor[] constructors = metricsClass.getConstructors();
        constructors[0].newInstance(METRICS_REPORTER_NAME, this._metricRegistry, metricsServerURL);
      } catch (final Exception e) {
        throw new IllegalStateException("Encountered error while loading and instantiating " + metricsReporterClassName,
            e);
      }
    } else {
      log.error(
          String.format("No value for property: %s or %s was found", LivyConf.CUSTOM_METRICS_REPORTER_CLASS_NAME(),
              LivyConf.METRICS_REPORTER_SERVER_URL()));
    }
  }
}
