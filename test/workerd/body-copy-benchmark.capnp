# SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
# SPDX-License-Identifier: Apache-2.0

using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "body-copy-benchmark", worker = .benchmarkWorker),
  ],
  sockets = [],
);

const benchmarkWorker :Workerd.Worker = (
  modules = [
    (name = "body-copy-benchmark.js", esModule = embed "body-copy-benchmark.js"),
  ],
  compatibilityDate = "2026-07-01",
);
