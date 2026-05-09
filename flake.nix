{
  description = "spoofdpi - Simple and fast anti-censorship tool to bypass DPI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        manifest = builtins.fromJSON (builtins.readFile ./.manifest.json);
        version = manifest.".";
        go = pkgs.go_1_26;
      in
      {
        packages.default = pkgs.buildGoModule {
          inherit version go;
          pname = "spoofdpi";
          src = self;
          vendorHash = "sha256-7fCyZQnnaoFqjdN89NwUAeujZJvmQnV+lYUbwtNGXMc=";
          subPackages = [ "cmd/spoofdpi" ];
          buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [ pkgs.libpcap ];
          env.CGO_ENABLED = if pkgs.stdenv.isDarwin then "1" else "0";
          ldflags = [
            "-s"
            "-w"
            "-X main.version=${version}"
            "-X main.build=flake"
            "-X main.commit=${self.shortRev or "dirty"}"
          ];
          meta = {
            description = "Simple and fast anti-censorship tool written in Go";
            homepage = "https://github.com/xvzc/spoofdpi";
            license = pkgs.lib.licenses.asl20;
          };
        };

        devShells.default = import ./shell.nix { inherit pkgs; };
      }
    );
}
