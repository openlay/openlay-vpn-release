-- Per static IP: list of CIDRs the device is allowed to reach (AllowedIPs in WireGuard sense).
-- Empty array = no restriction set by admin (client uses its own default).
ALTER TABLE device_static_ips
  ADD COLUMN IF NOT EXISTS allowed_ips TEXT[] NOT NULL DEFAULT '{}';
