{
  description = "enboxorg: Decentralized Web Node core in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, fenix, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
          };
        };

        # Rust toolchain with the mobile FFI targets used by the enbox-ffi
        # (UniFFI) crate. Apple targets back the Swift bindings; the Android
        # targets back the Kotlin bindings.
        rustToolchain = with fenix.packages.${system}; combine [
          stable.rustc
          stable.cargo
          stable.rustfmt
          stable.clippy
          stable.rust-src

          # iOS (Swift bindings) — linking requires macOS + Xcode.
          targets.aarch64-apple-ios.stable.rust-std
          targets.aarch64-apple-ios-sim.stable.rust-std
          targets.x86_64-apple-ios.stable.rust-std

          # Android (Kotlin bindings) — linking via the NDK / cargo-ndk.
          targets.aarch64-linux-android.stable.rust-std
          targets.armv7-linux-androideabi.stable.rust-std
          targets.x86_64-linux-android.stable.rust-std
          targets.i686-linux-android.stable.rust-std
        ];

        nativeBuildInputs = with pkgs; [
          rustToolchain
          cargo-make
          pkg-config
          openssl
          protobuf
        ];

        buildInputs = with pkgs; [
          openssl
          zlib
          libiconv
        ];

        # Android SDK/NDK used to cross-compile the FFI cdylib/staticlib for
        # the Android ABIs. cargo-ndk discovers the NDK via ANDROID_NDK_ROOT.
        androidComposition = pkgs.androidenv.composeAndroidPackages {
          includeNDK = true;
        };
        androidSdkRoot = "${androidComposition.androidsdk}/libexec/android-sdk";
        androidNdkRoot = "${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle";

        # Tooling for generating and cross-building the UniFFI bindings.
        ffiBuildInputs = with pkgs; [
          cargo-ndk
        ];

        ffiEnv = {
          ANDROID_HOME = androidSdkRoot;
          ANDROID_SDK_ROOT = androidSdkRoot;
          ANDROID_NDK_ROOT = androidNdkRoot;
          ANDROID_NDK_HOME = androidNdkRoot;
        };

        # Android ABIs to cross-build the FFI library for.
        androidAbis = [ "arm64-v8a" "armeabi-v7a" "x86_64" "x86" ];

        commonVersion = "0.1.0";
        commonCargoLock = {
          lockFile = ./Cargo.lock;
          allowBuiltinFetchGit = true;
        };

        commonEnv = {
          RUST_BACKTRACE = "1";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
        };

        # Common package metadata
        commonMeta = with pkgs.lib; {
          homepage = "https://github.com/enboxorg/enbox-rust-core";
          license = licenses.asl20;
          maintainers = [ ];
        };

        # Helper function to create Rust packages
        mkRustPackage = { pname, description, cargoBuildFlags ? [ ], checkFlags ? [ ] }:
          pkgs.rustPlatform.buildRustPackage {
            inherit pname cargoBuildFlags checkFlags;
            version = commonVersion;
            src = self;
            cargoLock = commonCargoLock;
            inherit nativeBuildInputs buildInputs;
            inherit (commonEnv) RUST_BACKTRACE PKG_CONFIG_PATH;
            meta = commonMeta // { inherit description; };
          };

        # Helper function to create check packages
        mkCheck = { pname, description, command, installResult }:
          pkgs.rustPlatform.buildRustPackage {
            inherit pname;
            version = commonVersion;
            src = self;
            cargoLock = commonCargoLock;
            inherit nativeBuildInputs buildInputs;
            inherit (commonEnv) RUST_BACKTRACE PKG_CONFIG_PATH;

            buildPhase = command;
            installPhase = ''
              mkdir -p $out
              echo "${installResult}" > $out/result
            '';

            meta = commonMeta // { inherit description; };
          };

        # Generate Swift + Kotlin UniFFI bindings from the native enbox-ffi
        # library, using the flake-pinned toolchain and uniffi-bindgen. Runs
        # impurely against the current checkout (writes crates/enbox-ffi/generated).
        ffiBindingsApp = pkgs.writeShellApplication {
          name = "enbox-ffi-bindings";
          runtimeInputs = nativeBuildInputs ++ buildInputs;
          text = ''
            export PKG_CONFIG_PATH="${commonEnv.PKG_CONFIG_PATH}"
            exec bash crates/enbox-ffi/generate-bindings.sh "$@"
          '';
        };

        # Cross-compile the FFI cdylib for every Android ABI via cargo-ndk and
        # the flake-pinned NDK, emitting a jniLibs/ tree. Pass an output dir as
        # the first argument (default ./target/jniLibs).
        ffiAndroidApp = pkgs.writeShellApplication {
          name = "enbox-ffi-android";
          runtimeInputs = nativeBuildInputs ++ buildInputs ++ ffiBuildInputs;
          text = ''
            ${pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList (name: value: "export ${name}=\"${toString value}\"") ffiEnv)}
            export PKG_CONFIG_PATH="${commonEnv.PKG_CONFIG_PATH}"
            out="''${1:-./target/jniLibs}"
            cargo ndk ${pkgs.lib.concatMapStringsSep " " (abi: "-t ${abi}") androidAbis} \
              -o "$out" build --release -p enbox-ffi
            echo "Android jniLibs written to $out"
          '';
        };

      in
      {
        packages = {
          # Default package - native build
          default = self.packages.${system}.dwn-rs;

          # Native build of the entire workspace
          dwn-rs = mkRustPackage {
            pname = "dwn-rs";
            description = "Decentralized Web Node implementation in Rust";
            cargoBuildFlags = [ "--workspace" ];
            checkFlags = [
              "--skip=test_remote"
            ];
          };

          # Core library only
          dwn-rs-core = mkRustPackage {
            pname = "dwn-rs-core";
            description = "DWN-RS core library";
            cargoBuildFlags = [ "-p" "dwn-rs-core" ];
          };

          # UniFFI facade — native cdylib/staticlib for the host platform.
          # Mobile (iOS/Android) artifacts are produced from the dev shell via
          # `cargo ndk` and `crates/enbox-ffi/generate-bindings.sh`.
          enbox-ffi = mkRustPackage {
            pname = "enbox-ffi";
            description = "UniFFI facade for Enbox native DWN integrations";
            cargoBuildFlags = [ "-p" "enbox-ffi" ];
          };
        };

        # Development shells
        devShells = {
          # Default development shell (native development)
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.dwn-rs ];

            buildInputs = nativeBuildInputs ++ buildInputs ++ ffiBuildInputs ++ (with pkgs; [
              # Development tools
              cargo-watch
              cargo-edit
              cargo-audit
              cargo-deny
              cargo-outdated

              # Documentation tools
              mdbook

              # Additional utilities
              jq
              curl
              bun
            ]);

            shellHook = ''
              echo "🦀 Enbox Rust Core Development Environment"
              echo "Rust version: $(rustc --version)"
              echo "Cargo version: $(cargo --version)"
              echo ""
              echo "Available commands:"
              echo "  cargo build                        # Build native version"
              echo "  cargo test                         # Run tests"
              echo "  cargo ndk -t arm64-v8a build       # Cross-build FFI for Android"
              echo "  crates/enbox-ffi/generate-bindings.sh  # Generate Swift/Kotlin bindings"
              echo ""
              echo "Workspace members:"
              echo "  - dwn-rs-core"
              echo "  - dwn-rs-stores"
              echo "  - dwn-rs-remote"
              echo "  - dwn-rs-message-derive"
              echo "  - enbox-ffi"

              # FFI / Android cross-compilation environment
              ${pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList (name: value: "export ${name}=\"${toString value}\"") ffiEnv)}
            '';
          };
        };

        # Formatter
        formatter = pkgs.nixpkgs-fmt;

        # Apps for easy execution
        apps = {
          default = {
            type = "app";
            program = "${self.packages.${system}.dwn-rs}/bin/dwn-rs";
          };

          # Generate Swift/Kotlin bindings: `nix run .#ffi-bindings`
          ffi-bindings = {
            type = "app";
            program = "${ffiBindingsApp}/bin/enbox-ffi-bindings";
          };

          # Cross-build the FFI lib for all Android ABIs: `nix run .#ffi-android`
          ffi-android = {
            type = "app";
            program = "${ffiAndroidApp}/bin/enbox-ffi-android";
          };
        };

        # Checks for CI/CD
        checks = {
          dwn-rs-clippy = mkCheck {
            pname = "dwn-rs-clippy";
            description = "Clippy linting check for DWN-RS";
            command = "cargo clippy --workspace --all-targets -- -D warnings";
            installResult = "Clippy check passed";
          };

          dwn-rs-fmt = mkCheck {
            pname = "dwn-rs-fmt";
            description = "Format check for DWN-RS";
            command = "cargo fmt --all -- --check";
            installResult = "Format check passed";
          };
        };
      });
}
