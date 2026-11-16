{
  description = "Open Observability Framework (OOF) — OCSF v1.3.0 collectors, NixOS module, and Cloudflare Basin IaC";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      lib = nixpkgs.lib;

      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      linuxSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forSystems = systems: f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      restfulProviderMeta = {
        x86_64-linux = {
          goArch = "linux_amd64";
          url = "https://github.com/magodo/terraform-provider-restful/releases/download/v0.25.2/terraform-provider-restful_0.25.2_linux_amd64.zip";
          hash = "sha256-ielMDzEtDvQhO0bud2on9qXRFFIMCKRxb0/uTCbBb5E=";
        };
        aarch64-linux = {
          goArch = "linux_arm64";
          url = "https://github.com/magodo/terraform-provider-restful/releases/download/v0.25.2/terraform-provider-restful_0.25.2_linux_arm64.zip";
          hash = "sha256-xioab7PFE1RR9o6k7R9m2ZmrZUMj0QUmdW6D9vd9a98=";
        };
        x86_64-darwin = {
          goArch = "darwin_amd64";
          url = "https://github.com/magodo/terraform-provider-restful/releases/download/v0.25.2/terraform-provider-restful_0.25.2_darwin_amd64.zip";
          hash = "sha256-BRP/YvzkGllGLznhxGNvPIfm+NJO5XkHWQDT4PV/aZI=";
        };
        aarch64-darwin = {
          goArch = "darwin_arm64";
          url = "https://github.com/magodo/terraform-provider-restful/releases/download/v0.25.2/terraform-provider-restful_0.25.2_darwin_arm64.zip";
          hash = "sha256-UM7Jr+i1VinRyU1Heyb/ld6MyOMwT2wr/F2tO8zG3sw=";
        };
      };

      mkRestfulProvider =
        pkgs:
        let
          metaInfo =
            restfulProviderMeta.${pkgs.stdenv.hostPlatform.system}
              or (throw "Unsupported system for magodo/restful provider: ${pkgs.stdenv.hostPlatform.system}");
          zipSrc = pkgs.fetchurl {
            url = metaInfo.url;
            hash = metaInfo.hash;
          };
          version = "0.25.2";
          sourceAddress = "registry.terraform.io/magodo/restful";
        in
        pkgs.runCommand "terraform-provider-restful-${version}"
          {
            nativeBuildInputs = [ pkgs.unzip ];
            passthru = {
              provider-source-address = sourceAddress;
            };
          }
          ''
            work="$(mktemp -d)"
            unzip -q ${zipSrc} -d "$work"
            bin="$(find "$work" -maxdepth 2 -type f -name 'terraform-provider-restful*' | head -n 1)"
            if [ -z "$bin" ]; then
              echo "Could not locate terraform-provider-restful binary inside ${metaInfo.url}" >&2
              exit 1
            fi
            dest="$out/libexec/terraform-providers/${sourceAddress}/${version}/${metaInfo.goArch}"
            mkdir -p "$dest"
            cp "$bin" "$dest/terraform-provider-restful_${version}"
            chmod +x "$dest/terraform-provider-restful_${version}"
          '';

      mkOofTofu =
        pkgs:
        let
          restfulProvider = mkRestfulProvider pkgs;
        in
        pkgs.opentofu.withPlugins (p: [
          p.cloudflare_cloudflare
          restfulProvider
        ]);

      mkCollectorAssets =
        pkgs:
        let
          ocsfLuaStore = ./adapters/collect/fluent-bit-journald/ocsf.lua;
          vectorYamlSrc = ./adapters/collect/vector-journald/vector.yaml;
          fluentBitConfRaw = builtins.readFile ./adapters/collect/fluent-bit-journald/fluent-bit.conf;
          otelcolYamlSrc = ./adapters/collect/otel-collector-journald/otelcol.yaml;

          mkFluentBitConfig =
            {
              listenHost ? "127.0.0.1",
              otlpPort ? 4318,
              forwardPort ? 24225,
              dbPath ? null,
              extraConfigFiles ? [ ],
            }:
            let
              otlpBlockOld = "    Listen             127.0.0.1\n    Port               4318";
              otlpBlockNew = "    Listen             ${listenHost}\n    Port               ${toString otlpPort}";
              fwdInputPortOld = "    Port               24225";
              fwdInputPortNew = "    Port               ${toString forwardPort}";
              fwdOutputPortOld = "    Port                             24225";
              fwdOutputPortNew = "    Port                             ${toString forwardPort}";
              scriptLineOld = "    Script             ocsf.lua";
              scriptLineNew = "    Script             ${ocsfLuaStore}";
              systemdLineOld = "    Strip_Underscores  Off";
              systemdLineNew =
                "    Strip_Underscores  Off"
                + lib.optionalString (dbPath != null) "\n    DB                 ${dbPath}";

              rendered =
                assert lib.assertMsg (lib.hasInfix otlpBlockOld fluentBitConfRaw)
                  "fluent-bit.conf missing expected OTLP Listen/Port lines";
                assert lib.assertMsg (lib.hasInfix fwdInputPortOld fluentBitConfRaw)
                  "fluent-bit.conf missing expected forward input Port line";
                assert lib.assertMsg (lib.hasInfix fwdOutputPortOld fluentBitConfRaw)
                  "fluent-bit.conf missing expected forward output Port line";
                assert lib.assertMsg (lib.hasInfix scriptLineOld fluentBitConfRaw)
                  "fluent-bit.conf missing expected Script ocsf.lua line";
                assert lib.assertMsg (lib.hasInfix systemdLineOld fluentBitConfRaw)
                  "fluent-bit.conf missing expected Strip_Underscores line";
                lib.replaceStrings
                  [
                    otlpBlockOld
                    fwdInputPortOld
                    fwdOutputPortOld
                    scriptLineOld
                    systemdLineOld
                  ]
                  [
                    otlpBlockNew
                    fwdInputPortNew
                    fwdOutputPortNew
                    scriptLineNew
                    systemdLineNew
                  ]
                  fluentBitConfRaw
                + lib.concatMapStrings (f: "\n@INCLUDE ${f}\n") extraConfigFiles;
            in
            pkgs.writeText "oof-fluent-bit.conf" rendered;

          oofVectorConfig =
            pkgs.runCommand "oof-vector.yaml" { } ''
              cp ${vectorYamlSrc} "$out"
            '';

          oofFluentBitConfig = mkFluentBitConfig { };

          oofOtelcolConfig =
            pkgs.runCommand "oof-otelcol.yaml" { } ''
              cp ${otelcolYamlSrc} "$out"
            '';

          oofVector = pkgs.symlinkJoin {
            name = "oof-vector-${pkgs.vector.version}";
            paths = [ pkgs.vector ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram "$out/bin/vector" \
                --add-flags "--dangerously-allow-env-var-interpolation --config ${oofVectorConfig}"
            '';
            meta = pkgs.vector.meta // {
              mainProgram = "vector";
            };
          };

          oofFluentBit = pkgs.symlinkJoin {
            name = "oof-fluent-bit-${pkgs.fluent-bit.version}";
            paths = [ pkgs.fluent-bit ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram "$out/bin/fluent-bit" \
                --add-flags "-c ${oofFluentBitConfig}"
            '';
            meta = pkgs.fluent-bit.meta // {
              mainProgram = "fluent-bit";
            };
          };
        in
        {
          inherit
            mkFluentBitConfig
            oofVectorConfig
            oofFluentBitConfig
            oofOtelcolConfig
            oofVector
            oofFluentBit
            ;
        };

      parseHostPort =
        addr:
        let
          m = builtins.match "^(\\[[0-9a-fA-F:]+]|[A-Za-z0-9._-]+):([1-9][0-9]{0,4})$" addr;
          rawHost = if m == null then null else builtins.elemAt m 0;
          port = if m == null then null else lib.toInt (builtins.elemAt m 1);
          valid = m != null && port >= 1 && port <= 65535;
          bareHost = if !valid then "" else lib.removePrefix "[" (lib.removeSuffix "]" rawHost);
        in
        {
          inherit
            valid
            rawHost
            bareHost
            port
            ;
        };

      toClientHost =
        rawHost:
        if rawHost == "0.0.0.0" then
          "127.0.0.1"
        else if rawHost == "[::]" || rawHost == "::" then
          "[::1]"
        else
          rawHost;

      hostsCollide =
        aBare: bBare:
        aBare == bBare
        || aBare == "0.0.0.0"
        || bBare == "0.0.0.0"
        || aBare == "::"
        || bBare == "::";

      parseHttpUrlHostPort =
        url:
        let
          m = builtins.match "^(https?)://(\\[[0-9a-fA-F:]+]|[A-Za-z0-9._-]+)(:([1-9][0-9]{0,4}))?(/.*)?$" url;
          scheme = if m == null then null else builtins.elemAt m 0;
          rawHost = if m == null then null else builtins.elemAt m 1;
          portStr = if m == null then null else builtins.elemAt m 3;
          port =
            if m == null then
              null
            else if portStr == null then
              (if scheme == "https" then 443 else 80)
            else
              lib.toInt portStr;
          valid = m != null && port >= 1 && port <= 65535;
          bareHost = if !valid then "" else lib.removePrefix "[" (lib.removeSuffix "]" rawHost);
        in
        {
          inherit
            valid
            scheme
            rawHost
            bareHost
            port
            ;
        };

      isLocalBindTarget =
        targetBare: listenerBare:
        let
          loopbacks = [
            "127.0.0.1"
            "localhost"
            "::1"
          ];
          wildcards = [
            "0.0.0.0"
            "::"
          ];
        in
        targetBare == listenerBare
        || (
          lib.elem targetBare loopbacks
          && (lib.elem listenerBare (loopbacks ++ wildcards))
        );
    in
    {
      packages =
        forSystems allSystems (
          pkgs:
          {
            oof-tofu = mkOofTofu pkgs;
          }
          // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
            let
              assets = mkCollectorAssets pkgs;
            in
            {
              oof-vector-config = assets.oofVectorConfig;
              oof-fluent-bit-config = assets.oofFluentBitConfig;
              oof-otelcol-config = assets.oofOtelcolConfig;
              oof-vector = assets.oofVector;
              oof-fluent-bit = assets.oofFluentBit;
            }
          )
        );

      devShells = forSystems allSystems (
        pkgs:
        let
          oofTofu = mkOofTofu pkgs;
        in
        {
          default = pkgs.mkShell {
            packages = [
              oofTofu
              pkgs.nodejs
              pkgs.typescript
              pkgs.pulumi
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.vector
              pkgs.fluent-bit
            ];
          };
        }
      );

      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          utils,
          ...
        }:
        let
          cfg = config.services.oof-collector;
          assets = mkCollectorAssets pkgs;

          httpParsed = parseHostPort cfg.otlp.httpListen;
          grpcParsed = parseHostPort cfg.otlp.grpcListen;
          bridgeGrpcParsed = parseHostPort cfg.otelBridge.grpcListen;
          bridgeHttpParsed = parseHostPort cfg.otelBridge.httpListen;
          bridgeTargetParsed = parseHttpUrlHostPort cfg.otelBridge.bridgeEndpoint;

          customFluentBitConfig = assets.mkFluentBitConfig {
            listenHost = if httpParsed.valid then httpParsed.bareHost else "127.0.0.1";
            otlpPort = if httpParsed.valid then httpParsed.port else 4318;
            forwardPort = cfg.fluentBit.forwardPort;
            dbPath = cfg.fluentBit.journaldDbPath;
            extraConfigFiles = cfg.extraConfigFiles;
          };

          activeListeners =
            (lib.optional (cfg.collector == "vector") {
              name = "services.oof-collector.otlp.grpcListen";
              parsed = grpcParsed;
            })
            ++ [
              {
                name = "services.oof-collector.otlp.httpListen";
                parsed = httpParsed;
              }
            ]
            ++ (lib.optional (cfg.collector == "fluent-bit") {
              name = "services.oof-collector.fluentBit.forwardPort";
              parsed = {
                valid = true;
                rawHost = "127.0.0.1";
                bareHost = "127.0.0.1";
                port = cfg.fluentBit.forwardPort;
              };
            })
            ++ (lib.optionals cfg.otelBridge.enable [
              {
                name = "services.oof-collector.otelBridge.grpcListen";
                parsed = bridgeGrpcParsed;
              }
              {
                name = "services.oof-collector.otelBridge.httpListen";
                parsed = bridgeHttpParsed;
              }
            ]);

          listenerPairs =
            let
              indexed = lib.imap0 (idx: item: { inherit idx item; }) activeListeners;
            in
            lib.concatMap (
              a:
              map (b: {
                first = a.item;
                second = b.item;
              }) (lib.filter (b: b.idx > a.idx) indexed)
            ) indexed;

          collidingPairs = lib.filter (
            pair:
            pair.first.parsed.valid
            && pair.second.parsed.valid
            && pair.first.parsed.port == pair.second.parsed.port
            && hostsCollide pair.first.parsed.bareHost pair.second.parsed.bareHost
          ) listenerPairs;

          selfLoopDetected =
            cfg.otelBridge.enable
            && bridgeHttpParsed.valid
            && bridgeTargetParsed.valid
            && bridgeTargetParsed.port == bridgeHttpParsed.port
            && isLocalBindTarget bridgeTargetParsed.bareHost bridgeHttpParsed.bareHost;
        in
        {
          options.services.oof-collector = {
            enable = lib.mkEnableOption "Open Observability Framework collector daemon";

            collector = lib.mkOption {
              type = lib.types.enum [
                "vector"
                "fluent-bit"
              ];
              default = "vector";
              description = "Collector implementation to run for host journald and OTLP normalization into OCSF v1.3.0.";
            };

            environmentFile = lib.mkOption {
              type = lib.types.strMatching "^/[^[:space:]]+$";
              description = ''
                Runtime systemd EnvironmentFile containing OOF_BASIN_ENDPOINT / OOF_BASIN_HOST
                and OOF_INGEST_TOKEN. Must point outside /nix/store.
              '';
            };

            vectorPackage = lib.mkPackageOption pkgs "vector" { };

            fluentBitPackage = lib.mkPackageOption pkgs "fluent-bit" { };

            otlp = {
              grpcListen = lib.mkOption {
                type = lib.types.str;
                default = if cfg.otelBridge.enable then "127.0.0.1:4319" else "127.0.0.1:4317";
                description = "Host:port for Vector OTLP gRPC ingestion (automatically shifts to 127.0.0.1:4319 when otelBridge.enable = true).";
              };

              httpListen = lib.mkOption {
                type = lib.types.str;
                default = if cfg.otelBridge.enable then "127.0.0.1:4320" else "127.0.0.1:4318";
                description = "Host:port for collector OTLP HTTP ingestion (automatically shifts to 127.0.0.1:4320 when otelBridge.enable = true).";
              };
            };

            fluentBit = {
              forwardPort = lib.mkOption {
                type = lib.types.port;
                default = 24225;
                description = "Authenticated loopback Forward TCP port used by Fluent Bit to strip OTLP group metadata.";
              };

              journaldDbPath = lib.mkOption {
                type = lib.types.nullOr (lib.types.strMatching "^/[^[:space:]]+$");
                default = "/var/lib/oof-collector/journald.db";
                description = "SQLite cursor DB path for Fluent Bit systemd input (null disables persistent DB tracking).";
              };
            };

            otelBridge = {
              enable = lib.mkEnableOption "co-located OpenTelemetry Collector OTLP bridge forwarding logs into oof-collector";

              package = lib.mkPackageOption pkgs "opentelemetry-collector-contrib" { };

              grpcListen = lib.mkOption {
                type = lib.types.str;
                default = "127.0.0.1:4317";
                description = "Host:port for OTel Collector OTLP gRPC receiver.";
              };

              httpListen = lib.mkOption {
                type = lib.types.str;
                default = "127.0.0.1:4318";
                description = "Host:port for OTel Collector OTLP HTTP receiver.";
              };

              bridgeEndpoint = lib.mkOption {
                type = lib.types.str;
                default =
                  let
                    hostPart = if httpParsed.valid then toClientHost httpParsed.rawHost else "127.0.0.1";
                    portPart = if httpParsed.valid then toString httpParsed.port else "4320";
                  in
                  "http://${hostPart}:${portPart}";
                description = "Downstream OTLP HTTP bridge destination URL (defaults to collector otlp.httpListen with wildcard mapped to loopback).";
              };

              extraConfigFiles = lib.mkOption {
                type = lib.types.listOf (lib.types.strMatching "^/[^[:space:]]+$");
                default = [ ];
                description = "Optional extra YAML configuration files merged by OTel Collector (--config=file:...).";
              };
            };

            extraConfigFiles = lib.mkOption {
              type = lib.types.listOf (lib.types.strMatching "^/[^[:space:]]+$");
              default = [ ];
              description = "Optional extra collector config fragments (passed via --config for Vector, @INCLUDE for Fluent Bit).";
            };

            extraEnvironment = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = { };
              description = "Additional non-secret environment variables passed to oof-collector.service.";
            };
          };

          config = lib.mkIf cfg.enable {
            assertions = [
              {
                assertion = !(lib.hasPrefix builtins.storeDir cfg.environmentFile);
                message = "services.oof-collector.environmentFile must NOT point inside /nix/store; store secrets out-of-band (sops-nix, agenix, or /run/secrets/...).";
              }
              {
                assertion = httpParsed.valid;
                message = "services.oof-collector.otlp.httpListen ('${cfg.otlp.httpListen}') must be a valid host:port.";
              }
              {
                assertion = (cfg.collector != "vector") || grpcParsed.valid;
                message = "services.oof-collector.otlp.grpcListen ('${cfg.otlp.grpcListen}') must be a valid host:port when using Vector.";
              }
              {
                assertion = (!cfg.otelBridge.enable) || (bridgeGrpcParsed.valid && bridgeHttpParsed.valid);
                message = "services.oof-collector.otelBridge.grpcListen/httpListen must be valid host:port values.";
              }
              {
                assertion = (!cfg.otelBridge.enable) || bridgeTargetParsed.valid;
                message = "services.oof-collector.otelBridge.bridgeEndpoint ('${cfg.otelBridge.bridgeEndpoint}') must be a valid http(s)://host:port URL.";
              }
              {
                assertion = collidingPairs == [ ];
                message =
                  "TCP listener port collision in services.oof-collector: "
                  + lib.concatMapStringsSep "; " (
                    p:
                    "${p.first.name} (${p.first.parsed.rawHost}:${toString p.first.parsed.port}) conflicts with ${p.second.name} (${p.second.parsed.rawHost}:${toString p.second.parsed.port})"
                  ) collidingPairs;
              }
              {
                assertion = !selfLoopDetected;
                message = "services.oof-collector.otelBridge.bridgeEndpoint ('${cfg.otelBridge.bridgeEndpoint}') must not point to its own otelBridge.httpListen (${cfg.otelBridge.httpListen}).";
              }
            ];

            systemd.services.oof-collector = {
              description = "Open Observability Framework Collector (${cfg.collector})";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];

              environment =
                (lib.optionalAttrs (cfg.collector == "vector") {
                  VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION = "true";
                  OOF_VECTOR_DATA_DIR = "/var/lib/oof-collector";
                  OOF_OTLP_GRPC_LISTEN = cfg.otlp.grpcListen;
                  OOF_OTLP_HTTP_LISTEN = cfg.otlp.httpListen;
                })
                // cfg.extraEnvironment;

              serviceConfig = {
                Type = "simple";
                DynamicUser = true;
                StateDirectory = "oof-collector";
                SupplementaryGroups = [ "systemd-journal" ];
                EnvironmentFile = cfg.environmentFile;
                Restart = "on-failure";
                RestartSec = "5s";
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                ExecStart = utils.escapeSystemdExecArgs (
                  if cfg.collector == "vector" then
                    [
                      (lib.getExe cfg.vectorPackage)
                      "--dangerously-allow-env-var-interpolation"
                      "--config"
                      assets.oofVectorConfig
                    ]
                    ++ lib.concatMap (f: [
                      "--config"
                      f
                    ]) cfg.extraConfigFiles
                  else
                    [
                      (lib.getExe cfg.fluentBitPackage)
                      "-c"
                      customFluentBitConfig
                    ]
                );
              };
            };

            systemd.services.oof-otel-bridge = lib.mkIf cfg.otelBridge.enable {
              description = "Open Observability Framework OTel Collector OTLP Bridge";
              wantedBy = [ "multi-user.target" ];
              after = [
                "network-online.target"
                "oof-collector.service"
              ];
              wants = [
                "network-online.target"
                "oof-collector.service"
              ];

              environment = {
                OOF_OTEL_GRPC_LISTEN = cfg.otelBridge.grpcListen;
                OOF_OTEL_HTTP_LISTEN = cfg.otelBridge.httpListen;
                OOF_OTLP_BRIDGE_ENDPOINT = cfg.otelBridge.bridgeEndpoint;
              };

              serviceConfig = {
                Type = "simple";
                DynamicUser = true;
                StateDirectory = "oof-otel-bridge";
                Restart = "on-failure";
                RestartSec = "5s";
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                ExecStart = utils.escapeSystemdExecArgs (
                  [
                    (lib.getExe cfg.otelBridge.package)
                    "--config=file:${assets.oofOtelcolConfig}"
                  ]
                  ++ map (f: "--config=file:${f}") cfg.otelBridge.extraConfigFiles
                );
              };
            };
          };
        };

      checks = forSystems allSystems (
        pkgs:
        let
          oofTofu = mkOofTofu pkgs;

          commonChecks = {
            terraform-validate =
              pkgs.runCommand "oof-terraform-validate"
                {
                  nativeBuildInputs = [ oofTofu ];
                }
                ''
                  work="$TMPDIR/repo"
                  mkdir -p "$work/contracts/ocsf" "$work/adapters/storage/cloudflare-basin-iceberg"
                  cp ${./contracts/ocsf/event-log-activity.basin.json} "$work/contracts/ocsf/event-log-activity.basin.json"
                  cp ${./adapters/storage/cloudflare-basin-iceberg/pipeline.sql} "$work/adapters/storage/cloudflare-basin-iceberg/pipeline.sql"
                  cp -r ${./adapters/storage/cloudflare-basin-iceberg/terraform} "$work/adapters/storage/cloudflare-basin-iceberg/terraform"
                  chmod -R u+w "$work"

                  export HOME="$TMPDIR/home"
                  mkdir -p "$HOME"
                  tfDir="$work/adapters/storage/cloudflare-basin-iceberg/terraform"
                  tofu -chdir="$tfDir" init -backend=false -input=false
                  tofu -chdir="$tfDir" validate
                  touch "$out"
                '';

            pulumi-typecheck = pkgs.buildNpmPackage {
              pname = "oof-pulumi-typecheck";
              version = "0.1.0";
              src = ./adapters/storage/cloudflare-basin-iceberg/pulumi;
              npmDepsHash = "sha256-h+oNul8u9t5dO0CnKxTn8SrH8eW5O1owMDpIFpt//1w=";
              npmFlags = [ "--ignore-scripts" ];
              dontNpmBuild = false;
              buildPhase = ''
                runHook preBuild
                npx --no-install tsc --noEmit
                runHook postBuild
              '';
              installPhase = ''
                runHook preInstall
                touch "$out"
                runHook postInstall
              '';
            };
          };

          linuxChecks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
            let
              assets = mkCollectorAssets pkgs;

              evalNixos =
                extraModule:
                lib.nixosSystem {
                  system = pkgs.stdenv.hostPlatform.system;
                  modules = [
                    self.nixosModules.default
                    (
                      { lib, ... }:
                      {
                        boot.isContainer = true;
                        system.stateVersion = "26.05";
                        networking.hostName = "oof-test";
                      }
                    )
                    extraModule
                  ];
                };

              checkAssertionsPass =
                evalResult:
                let
                  failed = map (a: a.message) (lib.filter (a: !a.assertion) evalResult.config.assertions);
                in
                failed == [ ];

              vecCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  extraConfigFiles = [ "/etc/oof/extra-transform.yaml" ];
                  extraEnvironment = {
                    RUST_LOG = "info";
                  };
                };
              };

              fbBridgeCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "fluent-bit";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otelBridge.enable = true;
                  extraConfigFiles = [ "/etc/oof/fb-extra.conf" ];
                };
              };

              fbCustomBindCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "fluent-bit";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.httpListen = "0.0.0.0:4322";
                  otelBridge.enable = true;
                };
              };

              badStoreEnvCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "${builtins.storeDir}/fake-secret.env";
                };
              };

              badPortCollisionCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.httpListen = "127.0.0.1:4318";
                  otelBridge.enable = true;
                  otelBridge.httpListen = "127.0.0.1:4318";
                };
              };

              badWildcardCollisionCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "fluent-bit";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.httpListen = "127.0.0.1:4320";
                  otelBridge.enable = true;
                  otelBridge.httpListen = "0.0.0.0:4320";
                };
              };

              badSelfLoopCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otelBridge.enable = true;
                  otelBridge.httpListen = "127.0.0.1:4318";
                  otelBridge.bridgeEndpoint = "http://localhost:4318";
                };
              };

              # Discard string context so nixpkgs#opentelemetry-collector-contrib is not compiled during flake check.
              fbUnitConfigMatch =
                builtins.match ".* \"?-c\"? \"?([^ \"]+)\"?.*"
                  (builtins.unsafeDiscardStringContext fbBridgeCfg.config.systemd.services.oof-collector.serviceConfig.ExecStart);

              evalSummary = builtins.unsafeDiscardStringContext (
                builtins.toJSON {
                  vecOk = checkAssertionsPass vecCfg;
                  vecExec = vecCfg.config.systemd.services.oof-collector.serviceConfig.ExecStart;
                  vecEnv = vecCfg.config.systemd.services.oof-collector.environment;
                  vecEnvFile = vecCfg.config.systemd.services.oof-collector.serviceConfig.EnvironmentFile;
                  vecDynUser = vecCfg.config.systemd.services.oof-collector.serviceConfig.DynamicUser;

                  fbBridgeOk = checkAssertionsPass fbBridgeCfg;
                  fbExec = fbBridgeCfg.config.systemd.services.oof-collector.serviceConfig.ExecStart;
                  fbOtelExec = fbBridgeCfg.config.systemd.services.oof-otel-bridge.serviceConfig.ExecStart;
                  fbOtelEnv = fbBridgeCfg.config.systemd.services.oof-otel-bridge.environment;
                  fbConfRef = if fbUnitConfigMatch == null then "" else builtins.elemAt fbUnitConfigMatch 0;

                  fbCustomOk = checkAssertionsPass fbCustomBindCfg;
                  fbCustomBridgeEndpoint = fbCustomBindCfg.config.systemd.services.oof-otel-bridge.environment.OOF_OTLP_BRIDGE_ENDPOINT;

                  badStoreRejected = !(checkAssertionsPass badStoreEnvCfg);
                  badCollisionRejected = !(checkAssertionsPass badPortCollisionCfg);
                  badWildcardRejected = !(checkAssertionsPass badWildcardCollisionCfg);
                  badSelfLoopRejected = !(checkAssertionsPass badSelfLoopCfg);
                }
              );

              actualFbBridgeConf = assets.mkFluentBitConfig {
                listenHost = "127.0.0.1";
                otlpPort = 4320;
                forwardPort = 24225;
                dbPath = "/var/lib/oof-collector/journald.db";
                extraConfigFiles = [ "/etc/oof/fb-extra.conf" ];
              };
            in
            {
              nixos-module-eval =
                pkgs.runCommand "oof-nixos-module-eval"
                  {
                    nativeBuildInputs = [ pkgs.nodejs ];
                    inherit evalSummary actualFbBridgeConf;
                  }
                  ''
                    node -e '
                      const assert = require("node:assert/strict");
                      const fs = require("node:fs");
                      const s = JSON.parse(process.env.evalSummary);
                      assert.equal(s.vecOk, true);
                      assert.match(s.vecExec, /--dangerously-allow-env-var-interpolation/);
                      assert.match(s.vecExec, /"--config" "\/etc\/oof\/extra-transform\.yaml"/);
                      assert.equal(s.vecEnv.OOF_VECTOR_DATA_DIR, "/var/lib/oof-collector");
                      assert.equal(s.vecEnv.OOF_OTLP_GRPC_LISTEN, "127.0.0.1:4317");
                      assert.equal(s.vecEnv.OOF_OTLP_HTTP_LISTEN, "127.0.0.1:4318");
                      assert.equal(s.vecEnv.RUST_LOG, "info");
                      assert.equal(s.vecEnvFile, "/run/secrets/oof-collector.env");
                      assert.equal(s.vecDynUser, true);

                      assert.equal(s.fbBridgeOk, true);
                      assert.match(s.fbOtelExec, /otelcol-contrib/);
                      assert.equal(s.fbOtelEnv.OOF_OTEL_GRPC_LISTEN, "127.0.0.1:4317");
                      assert.equal(s.fbOtelEnv.OOF_OTEL_HTTP_LISTEN, "127.0.0.1:4318");
                      assert.equal(s.fbOtelEnv.OOF_OTLP_BRIDGE_ENDPOINT, "http://127.0.0.1:4320");
                      assert.equal(s.fbConfRef, process.env.actualFbBridgeConf);

                      assert.equal(s.fbCustomOk, true);
                      assert.equal(s.fbCustomBridgeEndpoint, "http://127.0.0.1:4322");

                      assert.equal(s.badStoreRejected, true);
                      assert.equal(s.badCollisionRejected, true);
                      assert.equal(s.badWildcardRejected, true);
                      assert.equal(s.badSelfLoopRejected, true);

                      const fb = fs.readFileSync(process.env.actualFbBridgeConf, "utf8");
                      assert.match(fb, /Port               4320/);
                      assert.match(fb, /Script             \/nix\/store\/.*ocsf\.lua/);
                      assert.match(fb, /DB                 \/var\/lib\/oof-collector\/journald\.db/);
                      assert.match(fb, /@INCLUDE \/etc\/oof\/fb-extra\.conf/);
                    '
                    touch "$out"
                  '';

              ocsf-contracts =
                pkgs.runCommand "oof-ocsf-contracts"
                  {
                    nativeBuildInputs = [
                      pkgs.nodejs
                      oofTofu
                      pkgs.vector
                      pkgs.fluent-bit
                    ];
                  }
                  ''
                    export HOME="$TMPDIR/home"
                    mkdir -p "$HOME"
                    # Validate packaged collector configs too
                    VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
                      OOF_VECTOR_DATA_DIR="$TMPDIR/vec-data" \
                      OOF_BASIN_ENDPOINT="https://example-stream.ingest.cloudflare.com" \
                      OOF_INGEST_TOKEN="dummy-basin-token" \
                      vector validate --no-environment --dangerously-allow-env-var-interpolation ${assets.oofVectorConfig}

                    OOF_BASIN_HOST="example-stream.ingest.cloudflare.com" \
                      OOF_INGEST_TOKEN="dummy-basin-token" \
                      fluent-bit --dry-run -c ${assets.oofFluentBitConfig}

                    node --test ${self}/tests/ocsf-contracts.test.mjs
                    touch "$out"
                  '';
            }
          );
        in
        commonChecks // linuxChecks
      );
    };
}
