{
  pkgs ? import <nixpkgs> { },
}:
let
  golangciLint =
    let
      version = "2.12.1";
      url = "https://github.com/golangci/golangci-lint/releases/download";
      platform =
        {
          "aarch64-darwin" = "darwin-arm64";
          "x86_64-darwin" = "darwin-amd64";
          "aarch64-linux" = "linux-arm64";
          "x86_64-linux" = "linux-amd64";
        }
        .${pkgs.stdenv.hostPlatform.system};
    in
    pkgs.stdenv.mkDerivation {
      pname = "golangci-lint";
      inherit version;
      src = pkgs.fetchurl {
        url = "${url}/v${version}/golangci-lint-${version}-${platform}.tar.gz";
        hash = "sha256-OTpk75t1pbbIyL+IlbjYIIeQ5mkKQ94ZoS8/i8DprVI=";
      };
      sourceRoot = "golangci-lint-${version}-${platform}";
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
    go-task
    gopls
    golangci-lint-langserver
    golangciLint
    (pkgs.python312.withPackages (pyPkgs: with pyPkgs; [ mkdocs-material ]))
  ];

  shellHook = # sh
    ''
      export name="nix:spoofdpi"
    '';
}
