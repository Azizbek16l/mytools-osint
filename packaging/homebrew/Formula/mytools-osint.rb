# Personal-tap formula for Bluetm.uz / mytools-osint.
#
# Usage (once tap is created):
#   brew tap bluetm/osint
#   brew install mytools-osint
#
# This formula installs the CLI only (`osint` command). For the GUI, install
# the .pkg / .dmg directly from the GitHub release page.
class MytoolsOsint < Formula
  desc "Bluetm OSINT CLI — free APIs, no paid keys"
  homepage "https://github.com/Azizbek16l/mytools-osint"
  version "0.1.0"
  license "Proprietary"

  on_macos do
    on_arm do
      url "https://github.com/Azizbek16l/mytools-osint/releases/download/v#{version}/osint-macos-arm64"
      sha256 "REPLACE_WITH_ACTUAL_ARM64_SHA256_AFTER_RELEASE"
    end
    on_intel do
      url "https://github.com/Azizbek16l/mytools-osint/releases/download/v#{version}/osint-macos-x86_64"
      sha256 "REPLACE_WITH_ACTUAL_INTEL_SHA256_AFTER_RELEASE"
    end
  end

  on_linux do
    url "https://github.com/Azizbek16l/mytools-osint/releases/download/v#{version}/osint-linux-x86_64"
    sha256 "REPLACE_WITH_ACTUAL_LINUX_SHA256_AFTER_RELEASE"
  end

  def install
    bin.install Dir["osint-*"].first => "osint"
  end

  test do
    assert_match "mytools-osint", shell_output("#{bin}/osint --version")
  end
end
