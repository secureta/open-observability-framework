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
          vectorGhaYamlSrc = ./adapters/collect/vector-github-actions/vector.yaml;
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

          prometheusYamlSrc = ./adapters/collect/prometheus-pull/prometheus.yml;
          yamlFormat = pkgs.formats.yaml { };

          mkPrometheusConfig =
            {
              defaultScrapeInterval ? "30s",
              defaultScrapeTimeout ? "5s",
              targets ? { },
            }:
            let
              targetNames = lib.sort (a: b: a < b) (builtins.attrNames targets);
              scrapeConfigs = map (
                name:
                let
                  t = targets.${name};
                  parsed = parseHttpUrlHostPort t.endpoint;
                  metricsPath =
                    if parsed.urlPath == null || parsed.urlPath == "" || parsed.urlPath == "/" then
                      "/metrics"
                    else
                      parsed.urlPath;
                  effectiveInterval = if t.scrapeInterval != null then t.scrapeInterval else defaultScrapeInterval;
                  effectiveTimeout = if t.scrapeTimeout != null then t.scrapeTimeout else defaultScrapeTimeout;
                  keepLabels = [
                    "__name__"
                    "job"
                  ] ++ t.allowedLabels;
                in
                {
                  job_name = name;
                  scrape_interval = effectiveInterval;
                  scrape_timeout = effectiveTimeout;
                  metrics_path = metricsPath;
                  scheme = if parsed.scheme != null then parsed.scheme else "http";
                  honor_labels = false;
                  static_configs = [
                    {
                      targets = [ "${parsed.rawHost}:${toString parsed.port}" ];
                    }
                  ];
                  relabel_configs = [
                    {
                      target_label = "instance";
                      replacement = name;
                    }
                  ];
                  metric_relabel_configs = [
                    {
                      source_labels = [ "__name__" ];
                      regex = "^(${lib.concatStringsSep "|" t.metrics})$";
                      action = "keep";
                    }
                    {
                      regex = "^(${lib.concatStringsSep "|" keepLabels})$";
                      action = "labelkeep";
                    }
                  ];
                }
              ) targetNames;
            in
            yamlFormat.generate "oof-prometheus.yml" {
              global = {
                scrape_interval = defaultScrapeInterval;
                scrape_timeout = defaultScrapeTimeout;
              };
              scrape_configs = scrapeConfigs;
            };

          oofVectorConfig =
            pkgs.runCommand "oof-vector.yaml" { } ''
              cp ${vectorYamlSrc} "$out"
            '';

          oofVectorGhaConfig =
            pkgs.runCommand "oof-vector-github-actions.yaml" { } ''
              cp ${vectorGhaYamlSrc} "$out"
            '';

          oofFluentBitConfig = mkFluentBitConfig { };

          oofOtelcolConfig =
            pkgs.runCommand "oof-otelcol.yaml" { } ''
              cp ${otelcolYamlSrc} "$out"
            '';

          oofPrometheusConfig =
            pkgs.runCommand "oof-prometheus.yml" { } ''
              cp ${prometheusYamlSrc} "$out"
            '';

          oofVector = pkgs.symlinkJoin {
            name = "oof-vector-${pkgs.vector.version}";
            paths = [ pkgs.vector ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram "$out/bin/vector" \
                --set VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION "true" \
                --set-default VECTOR_CONFIG "${oofVectorConfig}"
            '';
            meta = pkgs.vector.meta // {
              mainProgram = "vector";
            };
          };

          oofVectorGha = pkgs.symlinkJoin {
            name = "oof-vector-github-actions-${pkgs.vector.version}";
            paths = [ pkgs.vector ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram "$out/bin/vector" \
                --set VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION "true" \
                --set-default VECTOR_CONFIG "${oofVectorGhaConfig}"
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

          oofPrometheus = pkgs.symlinkJoin {
            name = "oof-prometheus-${pkgs.prometheus.version}";
            paths = [
              pkgs.prometheus
              pkgs.prometheus.cli
            ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram "$out/bin/prometheus" \
                --add-flags "--config.file=${oofPrometheusConfig}" \
                --add-flags "--web.listen-address=127.0.0.1:9090"
            '';
            meta = pkgs.prometheus.meta // {
              mainProgram = "prometheus";
            };
          };
        in
        {
          inherit
            mkFluentBitConfig
            mkPrometheusConfig
            oofVectorConfig
            oofVectorGhaConfig
            oofFluentBitConfig
            oofOtelcolConfig
            oofPrometheusConfig
            oofVector
            oofVectorGha
            oofFluentBit
            oofPrometheus
            ;
        };

      parseIpv4Octets =
        s:
        let
          m = builtins.match "^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$" s;
          validOctet = o: (o == "0" || !(lib.hasPrefix "0" o)) && (lib.toInt o) <= 255;
        in
        if m != null && lib.all validOctet m then map lib.toInt m else null;

      hexDigitValues = {
        "0" = 0;
        "1" = 1;
        "2" = 2;
        "3" = 3;
        "4" = 4;
        "5" = 5;
        "6" = 6;
        "7" = 7;
        "8" = 8;
        "9" = 9;
        "a" = 10;
        "b" = 11;
        "c" = 12;
        "d" = 13;
        "e" = 14;
        "f" = 15;
      };

      isValidHextet = tok: builtins.match "^[0-9a-fA-F]{1,4}$" tok != null;

      hexToInt =
        tok:
        lib.foldl' (acc: ch: acc * 16 + hexDigitValues.${ch}) 0 (lib.stringToCharacters (lib.toLower tok));

      parseIpv6Words =
        s:
        if s == "" || lib.hasInfix ":::" s then
          null
        else
          let
            halves = lib.splitString "::" s;
            halfCount = lib.length halves;
          in
          if halfCount > 2 then
            null
          else
            let
              leftStr = builtins.elemAt halves 0;
              rightStr = if halfCount == 2 then builtins.elemAt halves 1 else "";
              leftTokens = if leftStr == "" then [ ] else lib.splitString ":" leftStr;
              rightTokens = if rightStr == "" then [ ] else lib.splitString ":" rightStr;
              rightLast = if rightTokens == [ ] then null else lib.last rightTokens;
              leftLast = if leftTokens == [ ] then null else lib.last leftTokens;
              ipv4InRight = halfCount == 2 && rightLast != null && lib.hasInfix "." rightLast;
              ipv4InLeft = halfCount == 1 && leftLast != null && lib.hasInfix "." leftLast;
              hasTrailingIpv4 = ipv4InRight || ipv4InLeft;
              ipv4Octets =
                if ipv4InRight then
                  parseIpv4Octets rightLast
                else if ipv4InLeft then
                  parseIpv4Octets leftLast
                else
                  null;
              ipv4Words =
                if !hasTrailingIpv4 then
                  [ ]
                else if ipv4Octets == null then
                  null
                else
                  [
                    ((builtins.elemAt ipv4Octets 0) * 256 + (builtins.elemAt ipv4Octets 1))
                    ((builtins.elemAt ipv4Octets 2) * 256 + (builtins.elemAt ipv4Octets 3))
                  ];
              leftHextets = if ipv4InLeft then lib.init leftTokens else leftTokens;
              rightHextets = if ipv4InRight then lib.init rightTokens else rightTokens;
              allHextets = leftHextets ++ rightHextets;
              groupCount = lib.length allHextets + (if hasTrailingIpv4 then 2 else 0);
              groupsValid =
                lib.all isValidHextet allHextets
                && (!hasTrailingIpv4 || ipv4Words != null);
              countValid = if halfCount == 1 then groupCount == 8 else groupCount <= 7;
            in
            if !(groupsValid && countValid) then
              null
            else if halfCount == 1 then
              (map hexToInt leftHextets) ++ ipv4Words
            else
              (map hexToInt leftHextets)
              ++ (lib.genList (_: 0) (8 - groupCount))
              ++ (map hexToInt rightHextets)
              ++ ipv4Words;

      ipv6WordsToCanonical =
        words:
        if lib.take 6 words == [ 0 0 0 0 0 65535 ] then
          let
            hi = builtins.elemAt words 6;
            lo = builtins.elemAt words 7;
            hiDiv = hi / 256;
            loDiv = lo / 256;
          in
          {
            kind = "ipv4";
            octets = [
              hiDiv
              (hi - hiDiv * 256)
              loDiv
              (lo - loDiv * 256)
            ];
          }
        else
          {
            kind = "ipv6";
            inherit words;
          };

      parseSocketAddr =
        addr:
        let
          m = builtins.match "^(\\[[0-9a-fA-F:.]+]|[0-9.]+):([1-9][0-9]{0,4})$" addr;
          rawHost = if m == null then null else builtins.elemAt m 0;
          port = if m == null then null else lib.toInt (builtins.elemAt m 1);
          portValid = port != null && port >= 1 && port <= 65535;
          isBracketed = rawHost != null && lib.hasPrefix "[" rawHost && lib.hasSuffix "]" rawHost;
          bareHost = if rawHost == null then "" else lib.removePrefix "[" (lib.removeSuffix "]" rawHost);
          canonical =
            if rawHost == null || !portValid then
              null
            else if isBracketed then
              let
                v6 = parseIpv6Words bareHost;
              in
              if v6 == null then null else ipv6WordsToCanonical v6
            else
              let
                v4 = parseIpv4Octets bareHost;
              in
              if v4 == null then null else {
                kind = "ipv4";
                octets = v4;
              };
          valid = canonical != null;
        in
        {
          inherit
            valid
            rawHost
            bareHost
            port
            canonical
            ;
        };

      toClientHost =
        parsed:
        if !parsed.valid then
          "127.0.0.1"
        else if parsed.canonical.kind == "ipv4" && parsed.canonical.octets == [ 0 0 0 0 ] then
          "127.0.0.1"
        else if parsed.canonical.kind == "ipv6" && parsed.canonical.words == [ 0 0 0 0 0 0 0 0 ] then
          "[::1]"
        else
          parsed.rawHost;

      isWildcardIpv4 = c: c.kind == "ipv4" && c.octets == [ 0 0 0 0 ];
      isWildcardIpv6 = c: c.kind == "ipv6" && c.words == [ 0 0 0 0 0 0 0 0 ];

      hostsCollide =
        aCanon: bCanon:
        aCanon == bCanon
        || isWildcardIpv6 aCanon
        || isWildcardIpv6 bCanon
        || (aCanon.kind == "ipv4" && bCanon.kind == "ipv4" && (isWildcardIpv4 aCanon || isWildcardIpv4 bCanon));

      parseHttpUrlHostPort =
        url:
        let
          m = builtins.match "^(https?)://(\\[[0-9a-fA-F:.]+]|[A-Za-z0-9._-]+)(:([1-9][0-9]{0,4}))?(/.*)?$" url;
          scheme = if m == null then null else builtins.elemAt m 0;
          rawHost = if m == null then null else builtins.elemAt m 1;
          portStr = if m == null then null else builtins.elemAt m 3;
          urlPath = if m == null then null else builtins.elemAt m 4;
          pathValid = urlPath == null || builtins.match "^/[^[:space:]?#]*$" urlPath != null;
          port =
            if m == null then
              null
            else if portStr == null then
              (if scheme == "https" then 443 else 80)
            else
              lib.toInt portStr;
          portValid = port != null && port >= 1 && port <= 65535;
          isBracketed = rawHost != null && lib.hasPrefix "[" rawHost && lib.hasSuffix "]" rawHost;
          bareHost = if rawHost == null then "" else lib.removePrefix "[" (lib.removeSuffix "]" rawHost);
          canonical =
            if rawHost == null || !portValid || !pathValid then
              null
            else if isBracketed then
              let
                v6 = parseIpv6Words bareHost;
              in
              if v6 == null then null else ipv6WordsToCanonical v6
            else if builtins.match "^[0-9.]+$" rawHost != null then
              let
                v4 = parseIpv4Octets rawHost;
              in
              if v4 == null then null else {
                kind = "ipv4";
                octets = v4;
              }
            else
              {
                kind = "dns";
                name = lib.removeSuffix "." (lib.toLower rawHost);
              };
          valid = canonical != null && !(isWildcardIpv4 canonical) && !(isWildcardIpv6 canonical);
        in
        {
          inherit
            valid
            scheme
            rawHost
            bareHost
            port
            urlPath
            canonical
            ;
        };

      parseDurationMs =
        dur:
        let
          m = builtins.match "^([1-9][0-9]*)(ms|s|m|h)$" dur;
          val = if m == null then null else lib.toInt (builtins.elemAt m 0);
          unit = if m == null then null else builtins.elemAt m 1;
          mult =
            if unit == "ms" then
              1
            else if unit == "s" then
              1000
            else if unit == "m" then
              60000
            else if unit == "h" then
              3600000
            else
              null;
        in
        if val == null || mult == null then null else val * mult;

      isLocalBindTarget =
        targetCanon: listenerCanon:
        if targetCanon.kind == "dns" then
          let
            isLocalDns = targetCanon.name == "localhost" || lib.hasSuffix ".localhost" targetCanon.name;
          in
          isLocalDns
          && (
            (listenerCanon.kind == "ipv4" && (builtins.elemAt listenerCanon.octets 0 == 127 || listenerCanon.octets == [ 0 0 0 0 ]))
            || (listenerCanon.kind == "ipv6" && (listenerCanon.words == [ 0 0 0 0 0 0 0 1 ] || listenerCanon.words == [ 0 0 0 0 0 0 0 0 ]))
          )
        else if targetCanon.kind == "ipv4" then
          let
            effectiveOctets = if isWildcardIpv4 targetCanon then [ 127 0 0 1 ] else targetCanon.octets;
          in
          (listenerCanon.kind == "ipv4" && (listenerCanon.octets == effectiveOctets || listenerCanon.octets == [ 0 0 0 0 ]))
          || isWildcardIpv6 listenerCanon
        else
          let
            effectiveWords = if isWildcardIpv6 targetCanon then [ 0 0 0 0 0 0 0 1 ] else targetCanon.words;
          in
          listenerCanon.kind == "ipv6" && (listenerCanon.words == effectiveWords || isWildcardIpv6 listenerCanon);
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
              oof-vector-github-actions-config = assets.oofVectorGhaConfig;
              oof-fluent-bit-config = assets.oofFluentBitConfig;
              oof-otelcol-config = assets.oofOtelcolConfig;
              oof-prometheus-config = assets.oofPrometheusConfig;
              oof-vector = assets.oofVector;
              oof-vector-github-actions = assets.oofVectorGha;
              oof-fluent-bit = assets.oofFluentBit;
              oof-prometheus = assets.oofPrometheus;
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
              pkgs.prometheus
              pkgs.prometheus.cli
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

          httpParsed = parseSocketAddr cfg.otlp.httpListen;
          grpcParsed = parseSocketAddr cfg.otlp.grpcListen;
          bridgeGrpcParsed = parseSocketAddr cfg.otelBridge.grpcListen;
          bridgeHttpParsed = parseSocketAddr cfg.otelBridge.httpListen;
          bridgeTargetParsed = parseHttpUrlHostPort cfg.otelBridge.bridgeEndpoint;
          ghaWebhookParsed = parseSocketAddr cfg.githubActionsWebhook.listen;
          promListenParsed = parseSocketAddr cfg.prometheus.listenAddress;

          promTargetEntries = lib.mapAttrsToList (
            name: target:
            let
              parsed = parseHttpUrlHostPort target.endpoint;
              effInterval = if target.scrapeInterval != null then target.scrapeInterval else cfg.prometheus.defaultScrapeInterval;
              effTimeout = if target.scrapeTimeout != null then target.scrapeTimeout else cfg.prometheus.defaultScrapeTimeout;
              intervalMs = parseDurationMs effInterval;
              timeoutMs = parseDurationMs effTimeout;
            in
            {
              inherit
                name
                target
                parsed
                effInterval
                effTimeout
                intervalMs
                timeoutMs
                ;
            }
          ) cfg.prometheus.targets;

          customPrometheusConfig = assets.mkPrometheusConfig {
            defaultScrapeInterval = cfg.prometheus.defaultScrapeInterval;
            defaultScrapeTimeout = cfg.prometheus.defaultScrapeTimeout;
            targets = cfg.prometheus.targets;
          };

          customFluentBitConfig = assets.mkFluentBitConfig {
            listenHost = if httpParsed.valid then httpParsed.bareHost else "127.0.0.1";
            otlpPort = if httpParsed.valid then httpParsed.port else 4318;
            forwardPort = cfg.fluentBit.forwardPort;
            dbPath = cfg.fluentBit.journaldDbPath;
            extraConfigFiles = cfg.extraConfigFiles;
          };

          activeListeners =
            (lib.optionals cfg.enable (
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
                  canonical = {
                    kind = "ipv4";
                    octets = [
                      127
                      0
                      0
                      1
                    ];
                  };
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
              ])
              ++ (lib.optional cfg.githubActionsWebhook.enable {
                name = "services.oof-collector.githubActionsWebhook.listen";
                parsed = ghaWebhookParsed;
              })
            ))
            ++ (lib.optional cfg.prometheus.enable {
              name = "services.oof-collector.prometheus.listenAddress";
              parsed = promListenParsed;
            });

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
            && hostsCollide pair.first.parsed.canonical pair.second.parsed.canonical
          ) listenerPairs;

          selfLoopDetected =
            cfg.otelBridge.enable
            && bridgeHttpParsed.valid
            && bridgeTargetParsed.valid
            && bridgeTargetParsed.port == bridgeHttpParsed.port
            && isLocalBindTarget bridgeTargetParsed.canonical bridgeHttpParsed.canonical;
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
                    hostPart = toClientHost httpParsed;
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

            githubActionsWebhook = {
              enable = lib.mkEnableOption "co-located Vector GitHub Actions webhook collector normalizing webhook events into OCSF v1.3.0";

              listen = lib.mkOption {
                type = lib.types.str;
                default = "127.0.0.1:8088";
                description = "Host:port for the GitHub Actions webhook HTTP server (/webhook/github).";
              };

              environmentFile = lib.mkOption {
                type = lib.types.nullOr (lib.types.strMatching "^/[^[:space:]]+$");
                default = null;
                description = "Optional separate systemd EnvironmentFile containing OOF_GITHUB_WEBHOOK_SECRET (defaults to services.oof-collector.environmentFile). Must point outside /nix/store.";
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

            prometheus = {
              enable = lib.mkEnableOption "Open Observability Framework Prometheus pull metrics collector (disabled by default)";

              package = lib.mkPackageOption pkgs "prometheus" { };

              listenAddress = lib.mkOption {
                type = lib.types.str;
                default = "127.0.0.1:9090";
                description = "Host:port for Prometheus HTTP query API (defaults to loopback 127.0.0.1:9090).";
              };

              retentionTime = lib.mkOption {
                type = lib.types.strMatching "^[1-9][0-9]*(y|w|d|h|m|s)$";
                default = "15d";
                description = "Local Prometheus TSDB retention duration (--storage.tsdb.retention.time).";
              };

              defaultScrapeInterval = lib.mkOption {
                type = lib.types.strMatching "^[1-9][0-9]*(ms|s|m|h)$";
                default = "30s";
                description = "Default Prometheus pull scrape interval.";
              };

              defaultScrapeTimeout = lib.mkOption {
                type = lib.types.strMatching "^[1-9][0-9]*(ms|s|m|h)$";
                default = "5s";
                description = "Default Prometheus pull scrape timeout (must be <= scrape interval).";
              };

              targets = lib.mkOption {
                type = lib.types.attrsOf (
                  lib.types.submodule {
                    options = {
                      endpoint = lib.mkOption {
                        type = lib.types.str;
                        description = "Prometheus /metrics HTTP(S) endpoint URL (examples are restricted to loopback, e.g. http://127.0.0.1:20241/metrics).";
                      };

                      scrapeInterval = lib.mkOption {
                        type = lib.types.nullOr (lib.types.strMatching "^[1-9][0-9]*(ms|s|m|h)$");
                        default = null;
                        description = "Optional per-target scrape interval override.";
                      };

                      scrapeTimeout = lib.mkOption {
                        type = lib.types.nullOr (lib.types.strMatching "^[1-9][0-9]*(ms|s|m|h)$");
                        default = null;
                        description = "Optional per-target scrape timeout override.";
                      };

                      metrics = lib.mkOption {
                        type = lib.types.listOf (lib.types.strMatching "^[a-zA-Z_:][a-zA-Z0-9_:]*$");
                        description = "Strict allowlist of Prometheus metric names to retain (all other metrics are dropped).";
                      };

                      allowedLabels = lib.mkOption {
                        type = lib.types.listOf (lib.types.strMatching "^[a-zA-Z_][a-zA-Z0-9_]*$");
                        default = [ ];
                        description = "Optional allowlist of extra labels to keep alongside __name__ and job (empty by default so tunnel IDs, IPs, hostnames, and instance labels are dropped).";
                      };
                    };
                  }
                );
                default = { };
                example = {
                  cloudflared = {
                    endpoint = "http://127.0.0.1:20241/metrics";
                    scrapeInterval = "30s";
                    scrapeTimeout = "5s";
                    metrics = [ "cloudflared_tunnel_ha_connections" ];
                  };
                };
                description = "Named Prometheus pull scrape targets with strict metric and label allowlists.";
              };
            };
          };

          config = lib.mkMerge [
            (lib.mkIf (cfg.enable || cfg.prometheus.enable) {
              assertions = [
                {
                  assertion = collidingPairs == [ ];
                  message =
                    "TCP listener port collision in services.oof-collector: "
                    + lib.concatMapStringsSep "; " (
                      p:
                      "${p.first.name} (${p.first.parsed.rawHost}:${toString p.first.parsed.port}) conflicts with ${p.second.name} (${p.second.parsed.rawHost}:${toString p.second.parsed.port})"
                    ) collidingPairs;
                }
              ];
            })

            (lib.mkIf cfg.enable {
              assertions = [
                {
                  assertion = !(lib.hasPrefix builtins.storeDir cfg.environmentFile);
                  message = "services.oof-collector.environmentFile must NOT point inside /nix/store; store secrets out-of-band (sops-nix, agenix, or /run/secrets/...).";
                }
                {
                  assertion = httpParsed.valid;
                  message = "services.oof-collector.otlp.httpListen ('${cfg.otlp.httpListen}') must be a valid IPv4/IPv6 socket address (ip:port, e.g. 127.0.0.1:4318 or [::1]:4318; DNS hostnames are rejected by Vector).";
                }
                {
                  assertion = (cfg.collector != "vector") || grpcParsed.valid;
                  message = "services.oof-collector.otlp.grpcListen ('${cfg.otlp.grpcListen}') must be a valid IPv4/IPv6 socket address (ip:port, e.g. 127.0.0.1:4317 or [::1]:4317) when using Vector.";
                }
                {
                  assertion = (!cfg.otelBridge.enable) || (bridgeGrpcParsed.valid && bridgeHttpParsed.valid);
                  message = "services.oof-collector.otelBridge.grpcListen/httpListen must be valid IPv4/IPv6 socket addresses (ip:port).";
                }
                {
                  assertion = (!cfg.otelBridge.enable) || bridgeTargetParsed.valid;
                  message = "services.oof-collector.otelBridge.bridgeEndpoint ('${cfg.otelBridge.bridgeEndpoint}') must be a valid non-wildcard http(s)://host:port URL (unspecified 0.0.0.0/[::] targets are not allowed).";
                }
                {
                  assertion = !selfLoopDetected;
                  message = "services.oof-collector.otelBridge.bridgeEndpoint ('${cfg.otelBridge.bridgeEndpoint}') must not point to its own otelBridge.httpListen (${cfg.otelBridge.httpListen}).";
                }
                {
                  assertion = (!cfg.githubActionsWebhook.enable) || ghaWebhookParsed.valid;
                  message = "services.oof-collector.githubActionsWebhook.listen ('${cfg.githubActionsWebhook.listen}') must be a valid IPv4/IPv6 socket address (ip:port, e.g. 127.0.0.1:8088).";
                }
                {
                  assertion =
                    (!cfg.githubActionsWebhook.enable)
                    || cfg.githubActionsWebhook.environmentFile == null
                    || !(lib.hasPrefix builtins.storeDir cfg.githubActionsWebhook.environmentFile);
                  message = "services.oof-collector.githubActionsWebhook.environmentFile must NOT point inside /nix/store.";
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

              systemd.services.oof-github-actions-webhook = lib.mkIf cfg.githubActionsWebhook.enable {
                description = "Open Observability Framework GitHub Actions Webhook Collector (Vector)";
                wantedBy = [ "multi-user.target" ];
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];

                environment = {
                  VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION = "true";
                  OOF_VECTOR_DATA_DIR = "/var/lib/oof-github-actions-webhook";
                  OOF_GHA_WEBHOOK_LISTEN = cfg.githubActionsWebhook.listen;
                };

                serviceConfig = {
                  Type = "simple";
                  DynamicUser = true;
                  StateDirectory = "oof-github-actions-webhook";
                  EnvironmentFile =
                    if cfg.githubActionsWebhook.environmentFile != null then
                      [
                        cfg.environmentFile
                        cfg.githubActionsWebhook.environmentFile
                      ]
                    else
                      cfg.environmentFile;
                  Restart = "on-failure";
                  RestartSec = "5s";
                  NoNewPrivileges = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  ExecStart = utils.escapeSystemdExecArgs [
                    (lib.getExe cfg.vectorPackage)
                    "--dangerously-allow-env-var-interpolation"
                    "--config"
                    assets.oofVectorGhaConfig
                  ];
                };
              };
            })

            (lib.mkIf cfg.prometheus.enable {
              assertions =
                [
                  {
                    assertion = promListenParsed.valid;
                    message = "services.oof-collector.prometheus.listenAddress ('${cfg.prometheus.listenAddress}') must be a valid IPv4/IPv6 socket address (ip:port, e.g. 127.0.0.1:9090 or [::1]:9090).";
                  }
                  {
                    assertion = promTargetEntries != [ ];
                    message = "services.oof-collector.prometheus.targets must define at least one scrape target when prometheus.enable = true.";
                  }
                  {
                    assertion =
                      (parseDurationMs cfg.prometheus.defaultScrapeTimeout)
                      <= (parseDurationMs cfg.prometheus.defaultScrapeInterval);
                    message = "services.oof-collector.prometheus.defaultScrapeTimeout ('${cfg.prometheus.defaultScrapeTimeout}') must not exceed defaultScrapeInterval ('${cfg.prometheus.defaultScrapeInterval}').";
                  }
                ]
                ++ lib.concatMap (
                  entry:
                  [
                    {
                      assertion = builtins.match "^[a-zA-Z0-9._-]+$" entry.name != null;
                      message = "services.oof-collector.prometheus.targets.${entry.name}: target name must match ^[a-zA-Z0-9._-]+$.";
                    }
                    {
                      assertion = entry.parsed.valid;
                      message = "services.oof-collector.prometheus.targets.${entry.name}.endpoint ('${entry.target.endpoint}') must be a valid non-wildcard http(s)://host[:port][/path] URL without query strings or fragments.";
                    }
                    {
                      assertion = entry.target.metrics != [ ];
                      message = "services.oof-collector.prometheus.targets.${entry.name}.metrics must specify at least one allowlisted metric name.";
                    }
                    {
                      assertion =
                        entry.timeoutMs != null
                        && entry.intervalMs != null
                        && entry.timeoutMs <= entry.intervalMs;
                      message = "services.oof-collector.prometheus.targets.${entry.name}: scrapeTimeout ('${entry.effTimeout}') must not exceed scrapeInterval ('${entry.effInterval}').";
                    }
                  ]
                ) promTargetEntries;

              systemd.services.oof-prometheus = {
                description = "Open Observability Framework Prometheus Pull Metrics Collector";
                wantedBy = [ "multi-user.target" ];
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];

                serviceConfig = {
                  Type = "simple";
                  DynamicUser = true;
                  StateDirectory = "oof-prometheus";
                  Restart = "on-failure";
                  RestartSec = "5s";
                  NoNewPrivileges = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  ExecStart = utils.escapeSystemdExecArgs [
                    (lib.getExe cfg.prometheus.package)
                    "--config.file=${customPrometheusConfig}"
                    "--storage.tsdb.path=/var/lib/oof-prometheus"
                    "--storage.tsdb.retention.time=${cfg.prometheus.retentionTime}"
                    "--web.listen-address=${cfg.prometheus.listenAddress}"
                  ];
                };
              };
            })
          ];
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

              vecIpv6Cfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.grpcListen = "[::1]:4319";
                  otlp.httpListen = "[::]:4320";
                  otelBridge.enable = true;
                };
              };

              ghaWebhookCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  githubActionsWebhook = {
                    enable = true;
                    listen = "127.0.0.1:8088";
                    environmentFile = "/run/secrets/oof-gha-webhook.env";
                  };
                };
              };

              badGhaPortCollisionCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.httpListen = "127.0.0.1:8088";
                  githubActionsWebhook = {
                    enable = true;
                    listen = "127.0.0.1:8088";
                  };
                };
              };

              badHostnameListenerCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.grpcListen = "localhost:4317";
                };
              };

              badIpv4OctetCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.httpListen = "999.0.0.1:4318";
                };
              };

              badIpv6SyntaxCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "fluent-bit";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.httpListen = "[:::]:4318";
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

              badIpv6AliasCollisionCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.grpcListen = "[::1]:4317";
                  otlp.httpListen = "[0:0:0:0:0:0:0:1]:4317";
                };
              };

              badIpv6AliasSelfLoopCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otelBridge.enable = true;
                  otelBridge.httpListen = "[0:0:0:0:0:0:0:1]:4318";
                  otelBridge.bridgeEndpoint = "http://[::1]:4318";
                };
              };

              badIpv4MappedCollisionCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.grpcListen = "127.0.0.1:4317";
                  otlp.httpListen = "[::ffff:127.0.0.1]:4317";
                };
              };

              badWildcardTargetIpv4Cfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otelBridge.enable = true;
                  otelBridge.httpListen = "127.0.0.1:4318";
                  otelBridge.bridgeEndpoint = "http://0.0.0.0:4318";
                };
              };

              badWildcardTargetIpv6Cfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otelBridge.enable = true;
                  otelBridge.httpListen = "[::1]:4318";
                  otelBridge.bridgeEndpoint = "http://[::]:4318";
                };
              };

              promDefaultDisabledCfg = evalNixos { };

              promEnabledCfg = evalNixos {
                services.oof-collector.prometheus = {
                  enable = true;
                  listenAddress = "127.0.0.1:9090";
                  defaultScrapeInterval = "30s";
                  defaultScrapeTimeout = "5s";
                  targets.cloudflared = {
                    endpoint = "http://127.0.0.1:20241/metrics";
                    scrapeInterval = "15s";
                    scrapeTimeout = "3s";
                    metrics = [ "cloudflared_tunnel_ha_connections" ];
                  };
                };
              };

              badPromEmptyTargetsCfg = evalNixos {
                services.oof-collector.prometheus = {
                  enable = true;
                };
              };

              badPromEmptyMetricsCfg = evalNixos {
                services.oof-collector.prometheus = {
                  enable = true;
                  targets.cloudflared = {
                    endpoint = "http://127.0.0.1:20241/metrics";
                    metrics = [ ];
                  };
                };
              };

              badPromTimeoutExceedsIntervalCfg = evalNixos {
                services.oof-collector.prometheus = {
                  enable = true;
                  targets.cloudflared = {
                    endpoint = "http://127.0.0.1:20241/metrics";
                    scrapeInterval = "5s";
                    scrapeTimeout = "10s";
                    metrics = [ "cloudflared_tunnel_ha_connections" ];
                  };
                };
              };

              badPromWildcardTargetCfg = evalNixos {
                services.oof-collector.prometheus = {
                  enable = true;
                  targets.cloudflared = {
                    endpoint = "http://0.0.0.0:20241/metrics";
                    metrics = [ "cloudflared_tunnel_ha_connections" ];
                  };
                };
              };

              badPromPortCollisionCfg = evalNixos {
                services.oof-collector = {
                  enable = true;
                  collector = "vector";
                  environmentFile = "/run/secrets/oof-collector.env";
                  otlp.httpListen = "127.0.0.1:9090";
                  prometheus = {
                    enable = true;
                    listenAddress = "127.0.0.1:9090";
                    targets.cloudflared = {
                      endpoint = "http://127.0.0.1:20241/metrics";
                      metrics = [ "cloudflared_tunnel_ha_connections" ];
                    };
                  };
                };
              };

              # Discard string context so nixpkgs#opentelemetry-collector-contrib is not compiled during flake check.
              fbUnitConfigMatch =
                builtins.match ".* \"?-c\"? \"?([^ \"]+)\"?.*"
                  (builtins.unsafeDiscardStringContext fbBridgeCfg.config.systemd.services.oof-collector.serviceConfig.ExecStart);

              promUnitConfigMatch =
                builtins.match ".*\"?--config\\.file=([^ \"]+)\"?.*"
                  (builtins.unsafeDiscardStringContext promEnabledCfg.config.systemd.services.oof-prometheus.serviceConfig.ExecStart);

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

                  vecIpv6Ok = checkAssertionsPass vecIpv6Cfg;
                  vecIpv6BridgeEndpoint = vecIpv6Cfg.config.systemd.services.oof-otel-bridge.environment.OOF_OTLP_BRIDGE_ENDPOINT;

                  ghaWebhookOk = checkAssertionsPass ghaWebhookCfg;
                  ghaWebhookExec = ghaWebhookCfg.config.systemd.services.oof-github-actions-webhook.serviceConfig.ExecStart;
                  ghaWebhookListen = ghaWebhookCfg.config.systemd.services.oof-github-actions-webhook.environment.OOF_GHA_WEBHOOK_LISTEN;
                  badGhaCollisionRejected = !(checkAssertionsPass badGhaPortCollisionCfg);

                  promDefaultDisabled = !(promDefaultDisabledCfg.config.services.oof-collector.prometheus.enable);
                  promDefaultHasUnit = builtins.hasAttr "oof-prometheus" promDefaultDisabledCfg.config.systemd.services;
                  promEnabledOk = checkAssertionsPass promEnabledCfg;
                  promExec = promEnabledCfg.config.systemd.services.oof-prometheus.serviceConfig.ExecStart;
                  promDynUser = promEnabledCfg.config.systemd.services.oof-prometheus.serviceConfig.DynamicUser;
                  promConfRef = if promUnitConfigMatch == null then "" else builtins.elemAt promUnitConfigMatch 0;

                  badHostnameRejected = !(checkAssertionsPass badHostnameListenerCfg);
                  badIpv4OctetRejected = !(checkAssertionsPass badIpv4OctetCfg);
                  badIpv6SyntaxRejected = !(checkAssertionsPass badIpv6SyntaxCfg);
                  badStoreRejected = !(checkAssertionsPass badStoreEnvCfg);
                  badCollisionRejected = !(checkAssertionsPass badPortCollisionCfg);
                  badWildcardRejected = !(checkAssertionsPass badWildcardCollisionCfg);
                  badSelfLoopRejected = !(checkAssertionsPass badSelfLoopCfg);
                  badIpv6AliasCollisionRejected = !(checkAssertionsPass badIpv6AliasCollisionCfg);
                  badIpv6AliasSelfLoopRejected = !(checkAssertionsPass badIpv6AliasSelfLoopCfg);
                  badIpv4MappedCollisionRejected = !(checkAssertionsPass badIpv4MappedCollisionCfg);
                  badWildcardTargetIpv4Rejected = !(checkAssertionsPass badWildcardTargetIpv4Cfg);
                  badWildcardTargetIpv6Rejected = !(checkAssertionsPass badWildcardTargetIpv6Cfg);
                  badPromEmptyTargetsRejected = !(checkAssertionsPass badPromEmptyTargetsCfg);
                  badPromEmptyMetricsRejected = !(checkAssertionsPass badPromEmptyMetricsCfg);
                  badPromTimeoutExceedsIntervalRejected = !(checkAssertionsPass badPromTimeoutExceedsIntervalCfg);
                  badPromWildcardTargetRejected = !(checkAssertionsPass badPromWildcardTargetCfg);
                  badPromPortCollisionRejected = !(checkAssertionsPass badPromPortCollisionCfg);
                }
              );

              actualFbBridgeConf = assets.mkFluentBitConfig {
                listenHost = "127.0.0.1";
                otlpPort = 4320;
                forwardPort = 24225;
                dbPath = "/var/lib/oof-collector/journald.db";
                extraConfigFiles = [ "/etc/oof/fb-extra.conf" ];
              };

              actualPromConf = assets.mkPrometheusConfig {
                defaultScrapeInterval = "30s";
                defaultScrapeTimeout = "5s";
                targets.cloudflared = {
                  endpoint = "http://127.0.0.1:20241/metrics";
                  scrapeInterval = "15s";
                  scrapeTimeout = "3s";
                  metrics = [ "cloudflared_tunnel_ha_connections" ];
                  allowedLabels = [ ];
                };
              };
            in
            {
              nixos-module-eval =
                pkgs.runCommand "oof-nixos-module-eval"
                  {
                    nativeBuildInputs = [
                      pkgs.nodejs
                      pkgs.prometheus.cli
                    ];
                    inherit evalSummary actualFbBridgeConf actualPromConf;
                  }
                  ''
                    promtool check config "$actualPromConf"
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

                      assert.equal(s.vecIpv6Ok, true);
                      assert.equal(s.vecIpv6BridgeEndpoint, "http://[::1]:4320");

                      assert.equal(s.ghaWebhookOk, true);
                      assert.match(s.ghaWebhookExec, /--dangerously-allow-env-var-interpolation/);
                      assert.equal(s.ghaWebhookListen, "127.0.0.1:8088");
                      assert.equal(s.badGhaCollisionRejected, true);

                      assert.equal(s.promDefaultDisabled, true);
                      assert.equal(s.promDefaultHasUnit, false);
                      assert.equal(s.promEnabledOk, true);
                      assert.equal(s.promDynUser, true);
                      assert.match(s.promExec, /--web\.listen-address=127\.0\.0\.1:9090/);
                      assert.match(s.promExec, /--storage\.tsdb\.path=\/var\/lib\/oof-prometheus/);
                      assert.equal(s.promConfRef, process.env.actualPromConf);

                      assert.equal(s.badHostnameRejected, true);
                      assert.equal(s.badIpv4OctetRejected, true);
                      assert.equal(s.badIpv6SyntaxRejected, true);
                      assert.equal(s.badStoreRejected, true);
                      assert.equal(s.badCollisionRejected, true);
                      assert.equal(s.badWildcardRejected, true);
                      assert.equal(s.badSelfLoopRejected, true);
                      assert.equal(s.badIpv6AliasCollisionRejected, true);
                      assert.equal(s.badIpv6AliasSelfLoopRejected, true);
                      assert.equal(s.badIpv4MappedCollisionRejected, true);
                      assert.equal(s.badWildcardTargetIpv4Rejected, true);
                      assert.equal(s.badWildcardTargetIpv6Rejected, true);
                      assert.equal(s.badPromEmptyTargetsRejected, true);
                      assert.equal(s.badPromEmptyMetricsRejected, true);
                      assert.equal(s.badPromTimeoutExceedsIntervalRejected, true);
                      assert.equal(s.badPromWildcardTargetRejected, true);
                      assert.equal(s.badPromPortCollisionRejected, true);

                      const fb = fs.readFileSync(process.env.actualFbBridgeConf, "utf8");
                      assert.match(fb, /Port               4320/);
                      assert.match(fb, /Script             \/nix\/store\/.*ocsf\.lua/);
                      assert.match(fb, /DB                 \/var\/lib\/oof-collector\/journald\.db/);
                      assert.match(fb, /@INCLUDE \/etc\/oof\/fb-extra\.conf/);

                      const prom = fs.readFileSync(process.env.actualPromConf, "utf8");
                      assert.match(prom, /job_name:\s*cloudflared/);
                      assert.match(prom, /127\.0\.0\.1:20241/);
                      assert.match(prom, /\^\(cloudflared_tunnel_ha_connections\)\$/);
                      assert.match(prom, /\^\(__name__\|job\)\$/);
                    '
                    touch "$out"
                  '';

              prometheus-metrics =
                pkgs.runCommand "oof-prometheus-metrics"
                  {
                    nativeBuildInputs = [
                      pkgs.nodejs
                      pkgs.prometheus
                      pkgs.prometheus.cli
                    ];
                  }
                  ''
                    export HOME="$TMPDIR/home"
                    mkdir -p "$HOME"
                    promtool check config ${assets.oofPrometheusConfig}
                    ${assets.oofPrometheus}/bin/prometheus --version
                    node --test ${self}/tests/prometheus-metrics.test.mjs
                    touch "$out"
                  '';

              finops-contracts =
                pkgs.runCommand "oof-finops-contracts"
                  {
                    nativeBuildInputs = [
                      pkgs.nodejs
                    ];
                  }
                  ''
                    export HOME="$TMPDIR/home"
                    mkdir -p "$HOME"
                    node --test ${self}/tests/finops-contracts.test.mjs
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
                    # Validate packaged collector configs and wrapper binaries too
                    OOF_VECTOR_DATA_DIR="$TMPDIR/vec-data" \
                      OOF_BASIN_ENDPOINT="https://example-stream.ingest.cloudflare.com" \
                      OOF_INGEST_TOKEN="dummy-basin-token" \
                      OOF_OTLP_GRPC_LISTEN="[::1]:4319" \
                      ${assets.oofVector}/bin/vector validate --no-environment

                    OOF_VECTOR_DATA_DIR="$TMPDIR/vec-gha-data" \
                      OOF_BASIN_ENDPOINT="https://example-stream.ingest.cloudflare.com" \
                      OOF_INGEST_TOKEN="dummy-basin-token" \
                      OOF_GITHUB_WEBHOOK_SECRET="dummy-webhook-secret" \
                      OOF_GHA_WEBHOOK_LISTEN="127.0.0.1:8088" \
                      ${assets.oofVectorGha}/bin/vector validate --no-environment

                    ${assets.oofVector}/bin/vector --version

                    OOF_BASIN_HOST="example-stream.ingest.cloudflare.com" \
                      OOF_INGEST_TOKEN="dummy-basin-token" \
                      ${assets.oofFluentBit}/bin/fluent-bit --dry-run

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
