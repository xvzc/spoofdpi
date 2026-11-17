{ pkgs, multiverse, ... }:

{
  enterShell = # sh
    ''
      export name="devenv:spoofdpi"
    '';
  packages = with pkgs; [
    libpcap
    go_1_26
    goreleaser
    gopls
    golangci-lint-langserver
    multiverse.golangci-lint."2.12.1"
    (pkgs.writeShellScriptBin "run" ''go build ./cmd/... && sudo ./spoofdpi "$@"'')
    (pkgs.python312.withPackages (pyPkgs: with pyPkgs; [ mkdocs-material ]))
    commitlint
  ];
}
