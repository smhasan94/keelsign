# Hardware

Development and test boards for keelsign (ticket SHA-31). Ordering is a human-only
step; this page is the procedure and the record.

## Bill of materials {#bom}

| Qty | Item | Role | Target | Suggested vendors |
|---|---|---|---|---|
| 1 | Nordic nRF52840-DK (Cortex-M4F) | Primary Cortex-M4F board | `thumbv7em-none-eabihf` | Mouser, DigiKey, Farnell |
| 2 | Raspberry Pi Pico 2 W (RP2350, Cortex-M33) | Cortex-M33 board; second unit as spare / probe host | `thumbv8m.main-none-eabihf` | Raspberry Pi approved resellers (e.g. Pimoroni, The Pi Hut, Adafruit), DigiKey |
| 1 | Raspberry Pi Debug Probe | SWD/UART probe for the Pico 2 W | — | Raspberry Pi approved resellers, DigiKey |
| 1 | ST NUCLEO-U575ZI-Q (STM32U575, Cortex-M33) | Cortex-M33 board with TrustZone | `thumbv8m.main-none-eabihf` | Mouser, DigiKey, Farnell, st.com |

SKUs / manufacturer part numbers: verify at checkout against the vendor listing (the
board names above are the manufacturer product names). Add USB cables (USB-C and
micro-USB) if not already on hand.

## Ordering procedure {#ordering}

1. Order every line of the [bill of materials](#bom), checking the SKU at checkout.
2. When each order ships, fill in the table below with vendor, order number and
   tracking number.
3. Paste the completed table as a comment on Linear ticket SHA-31. The acceptance
   criterion "Hardware ordered; tracking numbers on ticket" is ticked only once that
   comment exists.
4. When boards arrive, record the delivery date.

| Item | Qty | Vendor | Order no. | Tracking no. | Delivered |
|---|---|---|---|---|---|
| nRF52840-DK | 1 | | | | |
| Raspberry Pi Pico 2 W | 2 | | | | |
| Raspberry Pi Debug Probe | 1 | | | | |
| NUCLEO-U575ZI-Q | 1 | | | | |
