#!/bin/sh
# Local re-run of the JED checker's JAMSS step against exactly what ships in the installable ZIP.
# Downloads the original jamss.php at run time (it is GPL-3 and is NOT bundled here), extracts its
# patterns verbatim and applies them the same way jamss.php does ('#pattern#isS', same extensions).
#   usage:  sh tests/jamss_check.sh [--deep]        (needs php + curl)
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

curl -fsSL https://raw.githubusercontent.com/btoplak/Joomla-Anti-Malware-Scan-Script--JAMSS-/master/jamss.php -o "$TMP/jamss.php"
( echo '<?php'; awk '/Patterns Start/{f=1} f{print} /Patterns End/{f=0}' "$TMP/jamss.php" ) > "$TMP/patterns.php"

cat > "$TMP/scan.php" << 'PHP'
<?php
require __DIR__ . '/patterns.php';
$dir = $argv[1];
$patterns = array_merge($jamssPatterns, explode('|', $jamssStrings));
if (in_array('--deep', $argv, true)) { $patterns = array_merge($patterns, explode('|', $jamssDeepSearchStrings)); }
$ext = explode('|', 'php|php3|php4|php5|phps|htm|html|htaccess|gif|js');
$hits = 0; $files = 0;
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $f) {
    $path = $f->getPathname();
    if (!in_array(pathinfo($path, PATHINFO_EXTENSION), $ext, true) || !filesize($path)) { continue; }
    $files++; $content = file_get_contents($path);
    foreach ($patterns as $p) {
        preg_match_all('#' . (is_array($p) ? $p[0] : $p) . '#isS', $content, $m, PREG_OFFSET_CAPTURE);
        foreach ($m[0] as $match) {
            $hits++;
            printf("HIT %s line %d [%s]\n    %s\n", substr($path, strlen($dir)), substr_count(substr($content, 0, $match[1]), "\n") + 1,
                is_array($p) ? "Pattern #{$p[2]} - {$p[1]}" : "String '$p'", str_replace(["\n", "\r"], ' ', substr($content, $match[1], 90)));
        }
    }
}
printf("scanned %d files, %d hit(s)\n", $files, $hits);
exit($hits ? 1 : 0);
PHP

# only what the manifest ships (tests/, README, assets/ etc. are not part of the ZIP)
PKG="$TMP/pkg"; mkdir "$PKG"
for item in *.xml src fields services language media; do [ -e "$ROOT/$item" ] && cp -r "$ROOT/$item" "$PKG/"; done
php "$TMP/scan.php" "$PKG" "$@"
