# The web UI lays out at phone width

A wallet is phone software. The public demo is reached by scanning a QR code, an issuance arrives through a URL scheme the phone's browser dispatches, and the person debugging a flow is often holding the device the flow targets. So the web UI treats a narrow viewport as a first class layout, not as a shrunken desktop. Every view lays out down to 320px CSS width without horizontal scrolling.

The content this tool shows is hostile to narrow columns. A credential type is one long token (`urn:eu.europa.ec.eudi.university-diploma.extended-attestation-of-academic-achievement.v1`), a card can carry several badges next to that token, and a card row also holds action buttons. The credential card is the reference pattern for handling this:

- A row that cannot hold its parts wraps them. The action buttons move below the content (`flex-wrap` on the card, a `min-width` floor on the content column that forces the wrap) instead of squeezing the content into a sliver.
- An unbreakable token breaks where the line ends (`overflow-wrap: anywhere`), and only when the line ends.
- A badge is a unit. It wraps to the next line whole (`white-space: nowrap`) and never breaks inside its label.

## Consequences

A layout change is checked at narrow width before it ships, the same way a protocol change is checked against the specification. 375px (a common phone) and 320px (the floor) are the widths to look at. An element that forces horizontal scrolling at those widths is a defect. Old headless Chrome clamps its window to a desktop minimum, so narrow checks use device emulation (CDP `Emulation.setDeviceMetricsOverride`), not `--window-size`.
