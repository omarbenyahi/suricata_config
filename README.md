# Suricata Configuration

This repository contains Suricata IDS/IPS configuration files.

## Version
- Suricata 8.0.2 (Latest stable release)
- Installation date: November 25, 2025

## Files included:

- `suricata.yaml` - Main configuration file (configured for interface ens33)
- `classification.config` - Rule classifications
- `reference.config` - Reference configuration
- `threshold.config` - Threshold configuration

## Installation Steps

1. Install Suricata 8.0.2
2. Copy these files to `/etc/suricata/`
3. Update rules: `sudo suricata-update`
4. Restart service: `sudo systemctl restart suricata`

## Eve.json Output
The configuration enables eve.json logging at `/var/log/suricata/eve.json` for integration with analysis tools.
