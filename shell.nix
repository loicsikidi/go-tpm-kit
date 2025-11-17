let
  # golang pinned to 1.23.5
  # go to https://www.nixhub.io/packages/go to the list of available versions
  nixpkgs =
    fetchTarball
    "https://github.com/NixOS/nixpkgs/archive/01b6809f7f9d1183a2b3e081f0a1e6f8f415cb09.tar.gz";
  pkgs = import nixpkgs {
    config = {};
    overlays = [];
  };
  pre-commit = pkgs.callPackage ./.nix/precommit.nix {};

  gotest = pkgs.writeShellApplication {
    name = "gotest";
    runtimeInputs = [pkgs.go];
    text = ''
      paths=$(go list ./... | grep -vE '/proto') # exclude generated code
      if ! go test -count=1 -failfast -covermode=count -coverprofile=coverage.out -v "$paths"; then
        echo "tests failed ⛔"
        exit 1
      fi
      rm -f coverage.out
      echo "all tests passed 💫"
    '';
  };

  lint = pkgs.writeShellApplication {
    name = "lint";
    runtimeInputs = [pkgs.golangci-lint];
    text = ''
      if ! golangci-lint run ./...; then
        echo "linting issues found ⛔"
        exit 1
      fi
      echo "no linting issues found 💫"
    '';
  };
in
  pkgs.mkShellNoCC {
    packages = with pkgs; [
      go # v1.23.5
      delve
      golangci-lint

      # Required to run tests with -race flag
      gcc

      # Required for TPM simulator (go-tpm-tools)
      openssl

      # helper scripts
      gotest
      lint
    ];

    hardeningDisable = ["fortify"];

    shellHook = ''
      ${pre-commit.shellHook}
    '';
    buildInputs = pre-commit.enabledPackages;

    env = {
      # Required to run tests with -race flag
      CGO_ENABLED = "1";
    };
  }
