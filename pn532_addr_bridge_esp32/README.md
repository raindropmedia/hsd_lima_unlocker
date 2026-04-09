# PN532 UID Bridge (ESP32-C3)

Dieses Verzeichnis ist ein eigenstaendiges ESP-IDF-Projekt fuer den ESP32-C3.

## Zweck

Die Firmware arbeitet als UID-Bridge mit einem einfachen Modell:

- Downstream: ESP32 liest den PN532 dauerhaft per Software-I2C aus.
- Upstream: Das Host-Board macht nur I2C-Reads auf den ESP32-Slave.
- Antwort: Jeder Upstream-Read liefert ein festes 16-Byte UID-Statuspaket.

Es gibt kein Kommando-Forwarding vom Host zum PN532 mehr.

## Pinbelegung (aktuell)

- Upstream I2C-Slave (Host -> ESP32):
  - SDA: GPIO6
  - SCL: GPIO7
- Downstream Software-I2C (ESP32 -> PN532):
  - SDA: GPIO4
  - SCL: GPIO5
- PN532 Reset:
  - GPIO10

Wenn deine Verdrahtung anders ist, passe die Defines in `main/main.c` an.

## Upstream I2C Protokoll

### Slave-Adresse

- `0x25` (7-bit)

### Request (vom Host)

- Einfache I2C-Read-Transaktion auf Adresse `0x25`.
- Empfohlene Leselaenge: `16` Byte.
- Es ist kein vorheriger Write-Befehl erforderlich.

Kurzform:

- `START -> SLA+R(0x25) -> READ 16 Byte -> STOP`

### Response (16 Byte)

- Byte 0: Magic (`0xB1`)
- Byte 1: Statusbits
  - Bit0 (`0x01`): Karte vorhanden
  - Bit1 (`0x02`): Neue UID seit letztem Read
- Byte 2: UID-Laenge (`0..10`)
- Byte 3: Sequenznummer (inkrementiert bei neuer UID)
- Byte 4..13: UID-Daten (max. 10 Byte)
- Byte 14..15: reserviert (`0`)

Hinweis zu `Neue UID`:

- Das Flag `Bit1` ist ein One-Shot-Event und wird nach dem Read zurueckgesetzt.
- Solange dieselbe Karte liegen bleibt, bleibt `Karte vorhanden` gesetzt, aber `Neue UID` ist wieder `0`.

## Beispiel (Host-seitig)

Wenn eine 7-Byte UID erkannt wurde, kann die Antwort z. B. so aussehen:

```text
B1 03 07 2A 04 9F 12 34 56 78 90 00 00 00 00 00
```

Interpretation:

- `B1`: Magic ok
- `03`: Karte vorhanden + neue UID
- `07`: UID-Laenge 7
- `2A`: Sequenz
- `04 9F 12 34 56 78 90`: UID

## Build & Flash

Im Projektordner:

```bash
idf.py set-target esp32c3
idf.py build
idf.py -p <PORT> flash monitor
```

Typischer Port in deinem Setup:

```bash
idf.py -p /dev/tty.usbserial-110 flash monitor
```

## Hinweise

- ESP-IDF Setup in diesem Projekt: 5.5.3
- Der ESP32-C3 hat nur einen Hardware-I2C-Controller, daher nutzt der PN532-Pfad Software-I2C.
- Fuer stabile I2C-Pegel werden externe Pull-ups (z. B. 2.2k-4.7k) empfohlen.
