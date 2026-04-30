-- App server didn't carry a protocol field — implied tcp on the
-- firewall sync. Promote it to an explicit column so admin can
-- declare UDP services (DNS, NTP, internal game servers, …) or
-- both-side services (RDP TCP+UDP, VoIP signaling).
--
-- Wire-format values: 'tcp' | 'udp' | 'tcp+udp'. Stored as text with
-- check constraint; cheaper than an enum type for a 3-value set, and
-- easier to extend later.
ALTER TABLE application_servers
  ADD COLUMN protocol TEXT NOT NULL DEFAULT 'tcp'
    CHECK (protocol IN ('tcp', 'udp', 'tcp+udp'));
