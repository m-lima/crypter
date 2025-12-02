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
      flake-utils,
      helper,
      ...
    }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        options = {
          toolchains = fenixPkgs: [
            fenixPkgs.stable.toolchain
            fenixPkgs.targets.wasm32-unknown-unknown.stable.rust-std
          ];
          binary = false;
          hack = true;
          readme = true;
          bindgen = ./ffi/include/crypter.h;
        };
        base = helper.lib.rust.helper inputs system ./. options;
        ffi = helper.lib.rust.helper inputs system ./. (options // { features = [ "ffi" ]; });
        stream = helper.lib.rust.helper inputs system ./. (options // { features = [ "stream" ]; });
        all = helper.lib.rust.helper inputs system ./. (
          options
          // {
            features = [
              "ffi"
              "argon"
              "wasm"
              "stream"
            ];
          }
        );
        # wasm = (
        #   helper.lib.rust.helper inputs system ./. (
        #     options
        #     // {
        #       monolithic = true;
        #       toolchains = fenixPkgs: [
        #         fenixPkgs.stable.toolchain
        #         fenixPkgs.targets.wasm32-unknown-unknown.stable.rust-std
        #       ];
        #       nativeBuildInputs = pkgs: [ pkgs.wasm-bindgen-cli ];
        #       features = [ "wasm" ];
        #       overrides = {
        #         commonArgs = {
        #           doCheck = false;
        #           cargoBuildCommand = "cargo build --profile release --verbose --target wasm32-unknown-unknown";
        #           CARGO_PROFILE = "release";
        #           CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
        #           env = { };
        #         };
        #         mainArgs = {
        #           postInstall = ''
        #             mkdir $out/pkg
        #             wasm-bindgen $out/lib/* --out-dir $out/pkg --web
        #           '';
        #         };
        #       };
        #     }
        #   )
        # );
      in
      base.outputs
      // {
        packages = {
          default = base.outputs.packages.default;
          ffi = ffi.outputs.packages.default;
          stream = stream.outputs.packages.default;
          # wasm = wasm.outputs.packages.default;
        };

        devShells = {
          default = all.outputs.devShells.default;
          # wasm = wasm.outputs.devShells.default;
        };
      }
    );
}
