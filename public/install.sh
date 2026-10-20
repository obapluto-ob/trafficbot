#!/usr/bin/env bash
# Site Scout Extension Auto-Installer — Mac & Linux
# Downloads the extension and launches Chrome/Brave with it loaded.

set -e
SCOUT_URL="__SCOUT_URL__"
EXT_DIR="$HOME/.local/share/SiteScoutExtension"
PROFILE_DIR="$HOME/.local/share/SiteScoutProfile"
ZIP="/tmp/site-scout-ext.zip"

echo ""
echo " Site Scout Extension Installer"
echo " ================================"
echo ""

# Download
echo " [1/4] Downloading extension..."
curl -sL "$SCOUT_URL/extension.zip" -o "$ZIP"
if [ ! -f "$ZIP" ]; then echo " ERROR: Download failed."; exit 1; fi

# Extract
echo " [2/4] Extracting..."
rm -rf "$EXT_DIR" && mkdir -p "$EXT_DIR"
unzip -q "$ZIP" -d "$EXT_DIR" && rm "$ZIP"
if [ ! -f "$EXT_DIR/manifest.json" ]; then echo " ERROR: Extraction failed."; exit 1; fi

# Create profile dir
mkdir -p "$PROFILE_DIR"

# Find browser
echo " [3/4] Finding browser..."
BROWSER=""
BROWSER_NAME=""

for candidate in \
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
  "$(which google-chrome 2>/dev/null)" \
  "$(which google-chrome-stable 2>/dev/null)" \
  "$(which chromium-browser 2>/dev/null)" \
  "$(which chromium 2>/dev/null)" \
  "$(which brave-browser 2>/dev/null)"; do
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    BROWSER="$candidate"
    BROWSER_NAME=$(basename "$candidate")
    break
  fi
done

if [ -z "$BROWSER" ]; then
  echo " ERROR: No supported browser found (Chrome / Brave / Edge)."
  echo " Install Chrome then run this script again."
  exit 1
fi

# Write desktop shortcut (Linux)
if [ "$(uname)" = "Linux" ]; then
  SHORTCUT="$HOME/.local/share/applications/site-scout-session.desktop"
  mkdir -p "$(dirname "$SHORTCUT")"
  cat > "$SHORTCUT" <<EOF
[Desktop Entry]
Name=Site Scout Session
Exec="$BROWSER" --user-data-dir="$PROFILE_DIR" --load-extension="$EXT_DIR" --no-first-run "$SCOUT_URL/cookies"
Type=Application
Terminal=false
EOF
  chmod +x "$SHORTCUT"
fi

echo " [4/4] Launching $BROWSER_NAME with extension..."
echo ""
echo " Done! A 'Site Scout Session' shortcut was added to your apps."
echo " Use that shortcut next time — no need to run this again."
echo ""

"$BROWSER" --user-data-dir="$PROFILE_DIR" --load-extension="$EXT_DIR" --no-first-run "$SCOUT_URL/cookies" &
