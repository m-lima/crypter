{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    crane.url = "github:ipetkov/crane";
    fenix = {
      url = "github:nix-community/fenix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    helper.url = "github:m-lima/nix-template";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      helper,
      ...
    }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        bindgen = pkgs.buildWasmBindgenCli rec {
          src = pkgs.fetchCrate {
            pname = "wasm-bindgen-cli";
            version = "0.2.106";
            hash = "sha256-M6WuGl7EruNopHZbqBpucu4RWz44/MSdv6f0zkYw+44=";
          };

          cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
            inherit src;
            inherit (src) pname version;
            hash = "sha256-ElDatyOwdKwHg3bNH/1pcxKI7LXkhsotlDPQjiLHBwA=";
          };
        };
        options = {
          binary = false;
          hack = true;
          readme = true;
          bindgen = ./ffi/include/crypter.h;
          formatters = {
            clang-format.enable = true;
            djlint = {
              enable = true;
              indent = 2;
            };
            stylua = {
              enable = true;
              settings = {
                indent_type = "Spaces";
                indent_width = 2;
                quote_style = "AutoPreferSingle";
              };
            };
            xmllint.enable = true;
          };
          fmtExcludes = [
            "**/Makefile"
            "ffi/include/crypter.h"
          ];
        };
        wasmOptions = options // {
          toolchains = fenixPkgs: [
            fenixPkgs.stable.toolchain
            fenixPkgs.targets.wasm32-unknown-unknown.stable.rust-std
          ];
          features = [ "wasm" ];
          nativeBuildInputs = pkgs: [ bindgen ];
        };
        base = helper.lib.rust.helper inputs system ./. options;
        ffi = helper.lib.rust.helper inputs system ./. (options // { features = [ "ffi" ]; });
        stream = helper.lib.rust.helper inputs system ./. (options // { features = [ "stream" ]; });
        wasm =
          let
            wasm = helper.lib.rust.helper inputs system ./. (
              wasmOptions
              // {
                overrides = {
                  commonArgs = {
                    doCheck = false;
                    CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
                  };
                };
              }
            );
            name = "${wasm.mainArtifact.pname}";
            version = "${wasm.mainArtifact.version}";
          in
          wasm.craneLib.mkCargoDerivation (
            wasm.mainArgs
            // {
              cargoArtifacts = wasm.mainArtifact;
              buildPhaseCargoCommand = "wasm-bindgen target/lib/${name}.wasm --out-dir pkg --typescript --target bundler";
              installPhaseCommand = ''
                mkdir -p $out
                cp -r pkg $out/pkg
                cat > $out/pkg/package.json <<EOF
                {
                  "name": "${name}",
                  "type": "module",
                  "version": "${version}",
                  "files": [
                    "${name}_bg.wasm",
                    "${name}.js",
                    "${name}_bg.js",
                    "${name}.d.ts"
                  ],
                  "main": "${name}.js",
                  "types": "${name}.d.ts",
                  "sideEffects": [
                    "./${name}.js",
                    "./snippets/*"
                  ]
                }
                EOF
              '';
            }
          );
        all = helper.lib.rust.helper inputs system ./. (
          wasmOptions
          // {
            features = [
              "ffi"
              "argon"
              "wasm"
              "stream"
            ];
          }
        );
      in
      all.outputs
      // {
        packages = {
          inherit wasm;
          default = base.outputs.packages.default;
          ffi = ffi.outputs.packages.default;
          stream = stream.outputs.packages.default;
        };
      }
    );
}
