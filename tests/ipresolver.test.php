<?php
// Standalone assertions for Support\IpResolver (no Joomla needed):  php tests/ipresolver.test.php
declare(strict_types=1);

define('_JEXEC', 1);
require __DIR__ . '/../src/Support/IpResolver.php';

use FG\Plugin\System\Fgofflineipwhitelist\Support\IpResolver;

$fail = 0;
$check = static function (string $name, bool $ok) use (&$fail): void {
    echo ($ok ? 'OK   ' : 'FAIL ') . $name . "\n";
    $fail += $ok ? 0 : 1;
};
$m = static fn (string $ip, string $entry): bool => IpResolver::ipMatchesEntry($ip, $entry);

// IPv4-mapped IPv6 == the same IPv4, in both directions, exact and CIDR
$check('exact: ::ffff:192.0.2.1 == 192.0.2.1', $m('::ffff:192.0.2.1', '192.0.2.1'));
$check('exact: 192.0.2.1 == ::ffff:192.0.2.1', $m('192.0.2.1', '::ffff:192.0.2.1'));
$check('exact: hex form ::ffff:c000:201', $m('::ffff:c000:201', '192.0.2.1'));
$check('exact: different address rejected', !$m('::ffff:192.0.2.1', '192.0.2.2'));
$check('cidr: 192.0.2.0/24 matches mapped visitor', $m('::ffff:192.0.2.5', '192.0.2.0/24'));
$check('cidr: 192.0.2.0/24 rejects mapped 192.0.3.5', !$m('::ffff:192.0.3.5', '192.0.2.0/24'));
$check('cidr: mapped entry ::ffff:192.0.2.0/120 matches plain', $m('192.0.2.5', '::ffff:192.0.2.0/120'));
$check('cidr: mapped entry rejects other /24', !$m('192.0.3.5', '::ffff:192.0.2.0/120'));

// The mapped prefix is exactly ::ffff:0:0/96 - look-alikes must NOT be treated as IPv4
$check('IPv4-compatible ::192.0.2.1 is not 192.0.2.1', !$m('::192.0.2.1', '192.0.2.1'));
$check('NAT64 64:ff9b::192.0.2.1 is not 192.0.2.1', !$m('64:ff9b::192.0.2.1', '192.0.2.1'));
$check('::fffe:192.0.2.1 is not 192.0.2.1', !$m('::fffe:192.0.2.1', '192.0.2.1'));
$check('1::ffff:192.0.2.1 is not 192.0.2.1', !$m('1::ffff:192.0.2.1', '192.0.2.1'));

// Plain IPv4 / IPv6 unaffected
$check('v4 cidr 10.0.0.0/8 match', $m('10.5.5.5', '10.0.0.0/8'));
$check('v4 cidr 10.0.0.0/8 reject', !$m('11.5.5.5', '10.0.0.0/8'));
$check('v6 cidr 2001:db8::/32 match', $m('2001:db8::1', '2001:db8::/32'));
$check('v6 cidr 2001:db8::/32 reject', !$m('2001:db9::1', '2001:db8::/32'));
$check('v6 notation-independent exact match', $m('2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001'));
$check('v4 vs v6 rejected', !$m('2001:db8::1', '192.0.2.0/24'));
$check('garbage rejected', !$m('abc', '192.0.2.1') && !$m('192.0.2.1', 'abc/24') && !$m('192.0.2.1', '192.0.2.0/99'));

// parseList: CR, LF, CRLF and commas all separate; blanks dropped; trimmed
$check('parseList mixed separators', IpResolver::parseList("a\r\nb\rc\nd,e") === ['a', 'b', 'c', 'd', 'e']);
$check('parseList trims and drops empties', IpResolver::parseList("  x , y\r\n\r\n,\n z ") === ['x', 'y', 'z']);
$check('parseList empty input', IpResolver::parseList('') === [] && IpResolver::parseList(",,\n,\r\r") === []);

echo $fail === 0 ? "\nALL PASSED\n" : "\n{$fail} FAILED\n";
exit($fail === 0 ? 0 : 1);
