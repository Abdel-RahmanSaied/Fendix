# Homebrew formula for Fendix — hybrid API and code security scanner.
#
# To use this formula from a tap:
#   brew tap fendix/tap
#   brew install fendix
#
# Or install directly from the repository:
#   brew install --build-from-source ./Formula/fendix.rb

class Fendix < Formula
  desc "Hybrid API and code security scanner"
  homepage "https://github.com/fendix/fendix"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/fendix/fendix/releases/download/v#{version}/fendix-v#{version}-darwin-arm64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
    else
      url "https://github.com/fendix/fendix/releases/download/v#{version}/fendix-v#{version}-darwin-amd64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"
    end
  end

  on_linux do
    url "https://github.com/fendix/fendix/releases/download/v#{version}/fendix-v#{version}-linux-amd64"
    sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"
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
