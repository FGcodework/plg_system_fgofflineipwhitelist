# Tests

```bash
php tests/ipresolver.test.php     # IP/CIDR matching, IPv4-mapped IPv6, parseList - standalone, no Joomla
sh  tests/jamss_check.sh          # JED checker's JAMSS step, run locally against what ships in the ZIP
```

`jamss_check.sh` downloads the original `jamss.php` at run time (GPL-3, not bundled), applies its
patterns exactly as it does and exits non-zero on any hit. Add `--deep` for the (much noisier)
deep scan.
