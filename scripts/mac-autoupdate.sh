#!/usr/bin/env bash
# Install a launchd weekly auto-update for osint on macOS.
# Run once after installing osint; it sets up ~/Library/LaunchAgents/uz.bluetm.osint-autoupdate.plist
# and `launchctl load` it so the user-agent runs every Monday 09:00.
set -euo pipefail

PLIST="$HOME/Library/LaunchAgents/uz.bluetm.osint-autoupdate.plist"
LABEL="uz.bluetm.osint-autoupdate"
OSINT_BIN="$(command -v osint || echo "$HOME/.local/bin/osint")"

if [ ! -x "$OSINT_BIN" ]; then
  echo "osint not found on PATH — install it first via:" >&2
  echo "  curl -fsSL https://raw.githubusercontent.com/Azizbek16l/mytools-osint/main/scripts/install.sh | bash" >&2
  exit 1
fi

mkdir -p "$(dirname "$PLIST")"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>$LABEL</string>
  <key>ProgramArguments</key> <array>
    <string>$OSINT_BIN</string>
    <string>self-update</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key> <integer>1</integer>
    <key>Hour</key>    <integer>9</integer>
    <key>Minute</key>  <integer>0</integer>
  </dict>
  <key>RunAtLoad</key>           <false/>
  <key>StandardOutPath</key>     <string>$HOME/Library/Logs/osint-autoupdate.log</string>
  <key>StandardErrorPath</key>   <string>$HOME/Library/Logs/osint-autoupdate.log</string>
</dict>
</plist>
EOF

# Reload if already loaded
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "✓ installed auto-update: $PLIST"
echo "  next run: Monday 09:00"
echo "  log:      ~/Library/Logs/osint-autoupdate.log"
echo "  uninstall: launchctl bootout gui/$(id -u)/$LABEL && rm '$PLIST'"
