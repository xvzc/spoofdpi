{
  pkgs ? import <nixpkgs> { },
}:
let
  golangciLint =
    let
      version = "2.12.1";
      url = "https://github.com/golangci/golangci-lint/releases/download";
      meta =
        {
          "aarch64-darwin" = {
            platform = "darwin-arm64";
            hash = "sha256-OTpk75t1pbbIyL+IlbjYIIeQ5mkKQ94ZoS8/i8DprVI=";
          };
          "x86_64-darwin" = {
            platform = "darwin-amd64";
            hash = throw "golangci-lint: unsupported platform x86_64-darwin, add hash to shell.nix";
          };
          "aarch64-linux" = {
            platform = "linux-arm64";
            hash = throw "golangci-lint: unsupported platform aarch64-linux, add hash to shell.nix";
          };
          "x86_64-linux" = {
            platform = "linux-amd64";
            hash = "sha256-gseTLZqhDDTiLvVpYaxarXHUoUgGoaMbBpMa3SaIs2g=";
          };
        }
        .${pkgs.stdenv.hostPlatform.system};
    in
    pkgs.stdenv.mkDerivation {
      pname = "golangci-lint";
      inherit version;
      src = pkgs.fetchurl {
        url = "${url}/v${version}/golangci-lint-${version}-${meta.platform}.tar.gz";
        inherit (meta) hash;
      };
      sourceRoot = "golangci-lint-${version}-${meta.platform}";
      installPhase = ''
        runHook preInstall
        mkdir -p $out/bin
        install -m755 golangci-lint $out/bin/
        runHook postInstall
      '';
    };
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    libpcap
  ];
  packages = with pkgs; [
    go_1_26
    goreleaser
    gopls
    golangci-lint-langserver
    golangciLint
    (pkgs.writeShellScriptBin "run" ''go build ./cmd/... && sudo ./spoofdpi "$@"'')
    (pkgs.python312.withPackages (pyPkgs: with pyPkgs; [ mkdocs-material ]))
    commitlint
  ];

  shellHook = # sh
    ''
      export name="nix:spoofdpi"
    '';
}
