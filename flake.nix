{
  description = "pytr development shell";

  # Pinned by flake.lock. Only tooling comes from nixpkgs; Python dependencies stay pinned by uv.lock.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # uv installs prebuilt wheels and Python builds (ruff, mypyc-compiled mypy, curl_cffi) that expect a
      # standard Linux layout with a dynamic loader in /lib64. An FHS environment provides that, so
      # `uv sync --locked` / `uv run --locked ...` from CLAUDE.md work unchanged.
      packages = forAllSystems (pkgs: {
        default = pkgs.buildFHSEnv {
          name = "pytr-dev";
          targetPkgs =
            p: with p; [
              uv
              git
              stdenv.cc.cc.lib
              zlib
              openssl
            ];
          profile = ''
            # Let uv manage the interpreter (3.10-3.13 like CI) instead of picking up a Nix Python.
            export UV_PYTHON_PREFERENCE=only-managed
          '';
          runScript = "bash";
        };
      });

      # `nix develop` enters the FHS shell; `nix run . -- -c 'uv run --locked pytest'` runs one command in it.
      devShells = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.default.env;
      });
    };
}
