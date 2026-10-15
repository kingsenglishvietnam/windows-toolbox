# dns-adblock

System-wide ad and tracker blocking for Windows 11 using public DNS, with nothing installed: no
driver, no service, no proxy, no certificate.

## How it works

Ad and tracker domains resolve to nothing, so the connection is never attempted. The script points
every physical network adapter at AdGuard DNS (IPv4 and IPv6) and tells Windows' built-in DNS over
HTTPS client to use AdGuard's DoH endpoint, with fallback to plain DNS to the same servers, which
still filters.

Only name resolution changes. Nothing sits between your applications and the network. A filtering
driver or local proxy, by contrast, sits in the path of every connection, loopback ones included,
so a restart or reset of that filter can end local connections such as a Remote Desktop session.
DNS blocking does not add that failure mode.

## Usage

Run from an elevated PowerShell.

```powershell
& .\dns-adblock.ps1
```

1. Reports leftovers of an earlier system-wide ad blocker (AdBlock 360): its service, its driver,
   its install folder, root certificates from its HTTPS filtering, and any system proxy. It stops
   while the service or driver is still registered, because a filter in the path would muddy the
   result. `-Force` skips that check.
2. Registers AdGuard DNS with its DoH template.
3. Points every physical adapter at it (Wi-Fi, USB Wi-Fi, USB Ethernet).
4. Flushes the cache and proves it: a normal domain must resolve, an ad domain must come back
   blocked, and the DNS client should hold an HTTPS connection to AdGuard.

| Switch | Effect |
| --- | --- |
| `-PurgeCerts` | Also deletes root certificates whose subject or issuer mentions AdBlock. Windows asks for confirmation on any in the CurrentUser store. |
| `-Force` | Carries on even if the earlier blocker's service or driver is still registered. |
| `-Revert` | Puts every physical adapter back on DHCP-assigned DNS and removes the AdGuard DoH entries. |

## What it cannot do

- DNS cannot block ads served from the same domain as the content, such as YouTube, and it cannot
  hide page elements. Use blocking in the browser for those.
- AdGuard sees your DNS queries. DoH hides them from the network between you and AdGuard, not from
  AdGuard. If DoH fails, the fallback is plain DNS to AdGuard, visible to the network but still
  filtered.
- Networks that need their own DNS (corporate VPNs, captive portals, split-horizon setups) can
  break. Run `-Revert` on those.
