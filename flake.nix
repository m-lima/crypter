{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
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
      fenix,
      helper,
      ...
    }@inputs:
    helper.lib.rust.helper inputs {
      allowFilesets = [
        ./README.md
        ./README.tpl
        ./ffi/include/crypter.h
        ./cbindgen.toml
      ];
      binary = false;
      checks = {
        bindgen = ./ffi/include/crypter.h;
        readme = true;
      };
      hack = true;
      packages =
        {
          system,
          pkgs,
          lib,
          craneLib,
          prepareFeatures,
          mainArgs,
          cargoArtifacts,
        }:
        {
          ffi = craneLib.buildPackage (
            mainArgs
            // {
              inherit cargoArtifacts;
              cargoExtraArgs = mainArgs.cargoExtraArgs + " --features ffi";
              nativeBuildInputs = [ pkgs.rust-cbindgen ];
              postInstall = ''
                mkdir $out/include
                cbindgen . > $out/include/crypter.h
              '';
            }
          );
          stream = craneLib.buildPackage (
            mainArgs
            // {
              inherit cargoArtifacts;
              cargoExtraArgs = mainArgs.cargoExtraArgs + " --features stream";
            }
          );
          wasm =
            let
              fenixPkgs = fenix.packages.${system};
            in
            (craneLib.overrideToolchain (
              fenixPkgs.combine [
                fenixPkgs.stable.toolchain
                fenixPkgs.targets.wasm32-unknown-unknown.stable.rust-std
              ]
            )).buildPackage
              (
                mainArgs
                // {
                  inherit cargoArtifacts;
                  cargoBuildCommand = "cargo build --target wasm32-unknown-unknown --lib";
                  cargoExtraArgs = mainArgs.cargoExtraArgs + " --features wasm";
                  nativeBuildInputs = [ pkgs.wasm-bindgen-cli ];
                  postInstall = ''
                    mkdir $out/pkg
                    wasm-bindgen $out/lib/* --out-dir $out/pkg --web
                  '';
                }
              );
        };
    } ./. "crypter";
}
