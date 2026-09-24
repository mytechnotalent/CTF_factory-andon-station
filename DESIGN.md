# factory-andon-station - Design Blueprint (Act VII, IRON CHOIR)

Repo: `factory-andon-station`
Companion CTF repo: `CTF_factory-andon-station` (artifact prefix `ACT-VII`)
Codename: IRON CHOIR
Author: Kevin Thomas (kevin@mytechnotalent.com)

## Act VII of the OPERATION COLD IRON saga

Act I the lie. Act II the door. Act III the payload. Act IV the payload that
would not die. Act V the payload that spreads. Act VI the payload that steals.
Act VII is the payload that takes orders.

The andon station reports line faults to the floor. FROSTLINE's implant turns it
into a bot: it checks in with a command-and-control listener and executes
remotely issued tasks, so the Ministry can drive a fleet of stations in concert.
WHITEOUT must cut the C2 and clear the bot. This is the command-and-control
lesson.

## Safety contract

- No network, no internet, no host impact. Bare-metal RP2350, no OS.
- The C2 is a LOCAL classroom script. No external address.
- Tasks are benign (blink, log, report). Synthetic data only.
- Effects are confined to GPIO: the tower light, the LCD.
- A `SANDBOX_ONLY` build guard disables the implant.
- Every act ends in analysis and neutralization.

## Parity contract

Same repo layout, crypto stack, tooling, pin map, README top/footer standard,
telescreen disclaimer, and REAL flash persistence (flash_range_erase/program to
the last sector 0x103FF000) as Acts I-VI.

## Pin map (identical, new roles)

| Pin | Act VII role |
| --- | ------------ |
| DHT11 GP4 | line temperature |
| LCD SDA GP2 / SCL GP3 | andon status |
| IR GP5 | local fault-clear remote |
| Servo GP14 | line diverter |
| Red GP16 | FAULT |
| Yellow GP17 | ACK PENDING |
| Green GP18 | LINE OK |
| Button GP15 | fault clear |
| RYLR998 GP8/9 | andon link |
| Debug Probe | C2 analysis |
| Onboard GP25 | heartbeat |

## Fix track

- Fault frames must be sealed and authorized.
- Fault clear must not silently bypass authorization.
- The node must not execute remotely issued tasks (the C2 gate).

## Malware track (C2 / botnet, benign)

Module `include/implant.h` + `src/implant.c`, only under `SANDBOX_ONLY`:

- **Check-in.** Register with the local C2 listener with a bot id.
- **Tasking.** Execute remotely issued tasks (benign: blink, log, report).
- **Bot marker.** Program a bot marker into the reserved flash sector
  (`FACTORY_IMPLANT_RESERVE_ADDR` 0x103FF000) with the real flash API.
- **Anti-debug.** Reads DHCSR and behaves benignly under a probe.
- **Neutralization.** Disable check-in and tasking, clear the marker.

## Companion CTF: ACT-VII, four deep tasks

| Task | Points | Objective |
| ---- | ------ | --------- |
| 1 | 10 | Setup and analysis |
| 2 | 20 | Cut the C2 check-in |
| 3 | 20 | Stop the task handler |
| 4 | 20 | Clear the bot marker |
| 5 | 20 | Seal the fault-clear path (fix track) |
| 6 | 10 | Export, verify, hardware proof, reflection |

Every patch is in-place and same-size.

## Naming

Project `factory-andon-station`; companion `CTF_factory-andon-station`;
prefix `ACT-VII`.
