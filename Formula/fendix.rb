# Homebrew formula for Fendix — hybrid API and code security scanner.
#
# This formula is mirrored to the public install repo on every release.
# Users tap and install from the public repo:
#
#   brew tap Abdel-RahmanSaied/fendix
#   brew install fendix
#
# When editing this file, the canonical copy lives in this repo;
# release.yml regenerates it in the mirror with updated SHA256s.

class Fendix < Formula
  desc "Hybrid API and code security scanner"
  homepage "https://github.com/Abdel-RahmanSaied/homebrew-fendix"
  license "MIT"
  version "0.4.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/v#{version}/fendix-v#{version}-darwin-arm64"
      sha256 "7057c331fd75226e928f43827171bb55aa4aadc3c240b2884a9c7f6eaf4bf66a"
    else
      url "https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/v#{version}/fendix-v#{version}-darwin-amd64"
      sha256 "5efb4372fdd810424e4f94da609db0f339cde1ebdc5d75e403e542111574195e"
    end
  end

  on_linux do
    # linux/arm64 binary is planned for v1.0 (see Phase 13 / TASK-099).
    url "https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/v#{version}/fendix-v#{version}-linux-amd64"
    sha256 "6e5c332cc359890545bc9c499bcd571635e539040901ccd2fb9306897f560871"
  end

  depends_on "python@3.11" => :recommended

  def install
    bin.install Dir["fendix-*"].first => "fendix"
  end

  def caveats
    <<~EOS
      Fendix includes an embedded Python engine for whitebox analysis.
      For best results, ensure Python 3 is installed:
        brew install python@3.11

      Quick start:
        fendix scan --url https://api.example.com
        fendix scan --code ./src --spec openapi.yaml --format html -o report.html
    EOS
  end

  test do
    assert_match "fendix version", shell_output("#{bin}/fendix version")
  end
end
