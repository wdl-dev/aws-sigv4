# SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
# SPDX-License-Identifier: Apache-2.0

using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "aws-sigv4-smoke", worker = .smokeWorker),
  ],
  sockets = [],
);

const smokeWorker :Workerd.Worker = (
  modules = [
    (name = "smoke.js", esModule = embed "smoke.js"),
    (name = "@wdl-dev/aws-sigv4", esModule = embed "../../dist/index.js"),
  ],
  compatibilityDate = "2026-07-01",
);
