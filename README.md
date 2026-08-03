# WannaByte

<p align="center">
  <img src="images/WannaByte.png" alt="WannaByte logo" width="450">
</p> 

**The node that trusted the wrong voice.**

**WannaByte** is a father-and-son cybersecurity research project demonstrating how an insecure over-the-air firmware update process could allow unauthorized control of a Biscuit Node.

The proof of concept showed that affected ESP32-C5 Nodes could accept an unauthenticated OTA command over ESP-NOW, join a sender-controlled Wi-Fi network, download untrusted firmware, and install it without sufficient authenticity or integrity validation.

This was originally written for a school project. This was published publicly with the blessings of the vendor!  

> [Read the full WannaByte white paper](./WannaByte.pdf)

> [Watch the video demonstrating the attack](https://www.youtube.com/watch?v=5DBU0AyRgj4)

## Overview

The Biscuit Node communicates with a Biscuit Pro or Biscuit Ultra Core through ESP-NOW. In firmware versions earlier than **v1.2.9**, the Node accepted OTA commands containing Wi-Fi credentials and a firmware URL without verifying that the command came from an authorized Core.

At a high level, an unauthorized device within radio range could:

1. Send a crafted ESP-NOW OTA command.
2. Direct the Node to an attacker-controlled Wi-Fi network.
3. Provide an unauthorized firmware source.
4. Cause the Node to install the replacement firmware and reboot.

Because the command could be broadcast, multiple vulnerable Nodes in range could be affected. The proof of concept also demonstrated the potential for self-propagation by having replacement firmware repeat the same OTA instruction.

## Impact

Successful exploitation of the original issue could result in:

- Persistent unauthorized firmware execution
- Zero-click compromise within ESP-NOW radio range
- Complete loss of device confidentiality, integrity, and availability
- Broadcast impact against multiple vulnerable Nodes
- Potential propagation between affected devices

**CVSS v3.1:** `8.8 High`  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## Remediation Status

| Firmware | Status | Summary |
|---|---|---|
| Earlier than **Prod v1.2.9** | Vulnerable | Accepted unauthenticated OTA commands and attacker-supplied firmware locations without sufficient firmware verification. |
| **Prod v1.2.9** | Partial fix | Restricted updates to approved Beta or Production paths, but the firmware server's TLS identity was not fully verified. |
| **Beta v1.2.10/Prod v1.2.12** | Main takeover path remediated | Added certificate and hostname validation, an embedded GTS Root R4 trust anchor, explicit verification checks, and fail-closed clock synchronization. |

The unauthenticated OTA trigger could still cause repeated reboots in Beta v1.2.10/Prod v1.2.12, leaving a lower-impact denial-of-service condition.

## Responsible Disclosure

The issue was privately reported to the developer on **June 24, 2026**. The researchers evaluated the initial v1.2.9 remediation, identified the remaining firmware-server impersonation path, and disclosed it privately. Beta v1.2.10 was released on **July 13, 2026**, and firmware analysis confirmed that the new TLS verification controls were active on the OTA code path.

## Repository Scope

This repository is intended to document the vulnerability, proof-of-concept design, remediation process, and lessons learned. Detailed technical analysis, evidence, reverse-engineering notes, and the full disclosure timeline are provided in the attached white paper.

The project is not intended to provide a reusable attack tool or instructions for targeting third-party devices.

## Ethical Use

All testing was performed on equipment owned or controlled by the researchers. Use this material only for defensive research, education, or testing on systems you own or have explicit authorization to assess.

WannaByte highlights several core principles for secure firmware updates:

- Authenticate privileged commands.
- Reject unsolicited OTA requests.
- Validate TLS certificates and hostnames.
- Cryptographically verify firmware authenticity and integrity.
- Fail closed when trust cannot be established.

## Researchers

- **x0sin0x** — [GitHub](https://github.com/x0SiN0x)
- **x0jacob0x** — [GitHub](https://github.com/x0jac0b0x)
<img src="images/n3wb-logo.webp" alt="n3wb logo" width="150">

WannaByte was developed as a collaborative father-and-son security research project focused on embedded systems, wireless protocols, firmware analysis, and responsible vulnerability disclosure.

## Disclaimer

This material is provided for educational, defensive, and authorized security research purposes only. The authors are not responsible for misuse or unauthorized activity.
