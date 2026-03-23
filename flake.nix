{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = with pkgs; mkShell {
          buildInputs = [
            docker
            docker-buildx
          ];
          # Decorative prompt override so we know when we're in a dev shell
          shellHook = ''
            export PS1="[dev] $PS1"
          '';
        };
      });
}
