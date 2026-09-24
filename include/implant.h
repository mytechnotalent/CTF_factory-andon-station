// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/factory-andon-station
// File:    implant.h
// Desc:    Declares the SANDBOX_ONLY FROSTLINE command-and-control bot:
//          the local C2 check-in handshake, the benign remote task
//          handler, the reserved-sector bot marker, and the CoreDebug
//          anti-debug trap. Compiled only under SANDBOX_ONLY.
// Created: 2026

#ifndef IMPLANT_H
#define IMPLANT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Magic preamble that marks a FROSTLINE C2 command frame.
 */
#define ANDON_IMPLANT_C2_MAGIC "C2V1"

/**
 * @brief Length in bytes of the C2V1 command magic preamble.
 */
#define ANDON_IMPLANT_C2_MAGIC_LEN 4u

/**
 * @brief Bot identifier the implant registers with the C2 listener.
 */
#define ANDON_IMPLANT_BOT_ID 0xB7u

/**
 * @brief C2 task code that blinks the tower light.
 */
#define ANDON_IMPLANT_TASK_BLINK 0x01u

/**
 * @brief C2 task code that logs a synthetic line.
 */
#define ANDON_IMPLANT_TASK_LOG 0x02u

/**
 * @brief C2 task code that reports bot status.
 */
#define ANDON_IMPLANT_TASK_REPORT 0x03u

/**
 * @brief Total length in bytes of one C2 command frame.
 *
 * A frame is the magic preamble, the bot identifier, and the task byte.
 */
#define ANDON_IMPLANT_TASK_FRAME_LEN (ANDON_IMPLANT_C2_MAGIC_LEN + 2u)

/**
 * @brief Marker byte written into the reserved flash sector.
 */
#define ANDON_IMPLANT_MARKER_BYTE 0xC7u

/**
 * @brief Offset of the reserved flash sector used by the bot marker.
 *
 * The final 4 KiB sector of the 4 MiB flash, well beyond the firmware.
 */
#define ANDON_IMPLANT_RESERVE_OFFSET 0x3FF000u

/**
 * @brief Reserved flash sector address used by the bot marker.
 */
#define ANDON_IMPLANT_RESERVE_ADDR 0x103FF000u

/**
 * @brief CoreDebug DHCSR register address used by the anti-debug trap.
 */
#define ANDON_IMPLANT_DHCSR_ADDR 0xE000EDF0u

/**
 * @brief CoreDebug DHCSR bit that reports an enabled debugger.
 */
#define ANDON_IMPLANT_DHCSR_DEBUGEN 0x00000001u

/**
 * @brief CoreDebug DHCSR bit that reports a halted core.
 */
#define ANDON_IMPLANT_DHCSR_HALT 0x00000002u

/**
 * @brief Number of ticks between autonomous C2 check-ins.
 */
#define ANDON_IMPLANT_TICK_INTERVAL 4u

/**
 * @brief Initialize the implant and re-install from the reserved sector.
 *
 * On first run the implant writes its bot marker into the reserved flash
 * sector. On every later boot the marker is present, so the bot is
 * re-installed without any firmware change.
 *
 * @param void No parameters.
 * @return void
 */
void implant_init(void);

/**
 * @brief Advance the implant by one tick and check in with the C2.
 *
 * @param void No parameters.
 * @return void
 */
void implant_tick(void);

/**
 * @brief Register with the local C2 listener using the bot identifier.
 *
 * @param void No parameters.
 * @return bool true when a check-in frame was emitted.
 */
bool implant_check_in(void);

/**
 * @brief Handle one inbound C2 frame and run any issued task.
 *
 * @param frame Pointer to the inbound frame bytes.
 * @param len Number of inbound frame bytes.
 * @return void
 */
void implant_handle_command(const uint8_t *frame, size_t len);

/**
 * @brief Report whether the implant is armed.
 *
 * @param void No parameters.
 * @return bool true when the implant payload is armed.
 */
bool implant_armed(void);

/**
 * @brief Report whether a debug probe is attached via CoreDebug DHCSR.
 *
 * @param void No parameters.
 * @return bool true when C_DEBUGEN or C_HALT is set.
 */
bool implant_debug_attached(void);

/**
 * @brief Report whether the implant has checked in with the C2 listener.
 *
 * @param void No parameters.
 * @return bool true when at least one check-in frame was emitted.
 */
bool implant_checked_in(void);

/**
 * @brief Report whether the reserved-sector bot marker is set.
 *
 * @param void No parameters.
 * @return bool true when the bot marker occupies the reserved sector.
 */
bool implant_infected(void);

/**
 * @brief Enable or disable the C2 check-in path.
 *
 * @param enabled True to allow check-in, false to neutralize it.
 * @return void
 */
void implant_set_checkin(bool enabled);

/**
 * @brief Enable or disable the remote task handler.
 *
 * @param enabled True to allow tasking, false to neutralize it.
 * @return void
 */
void implant_set_tasking(bool enabled);

/**
 * @brief Clear the bot marker and disable check-in and tasking.
 *
 * @param void No parameters.
 * @return void
 */
void implant_neutralize(void);

/**
 * @brief Return the last benign C2 task code that was executed.
 *
 * @param void No parameters.
 * @return uint8_t Last executed task code, or zero when none ran.
 */
uint8_t implant_last_task(void);

/**
 * @brief Return the number of benign C2 tasks executed this boot.
 *
 * @param void No parameters.
 * @return size_t Number of executed tasks.
 */
size_t implant_task_count(void);

/**
 * @brief Return the number of C2 check-ins emitted this boot.
 *
 * @param void No parameters.
 * @return size_t Number of emitted check-ins.
 */
size_t implant_checkin_count(void);

#endif // IMPLANT_H
