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
// File:    implant.c
// Desc:    Implements the SANDBOX_ONLY FROSTLINE command-and-control bot:
//          the local C2 check-in handshake, the benign remote task
//          handler, the reserved-sector bot marker, and the CoreDebug
//          anti-debug trap. Compiled only under SANDBOX_ONLY.
// Created: 2026

#include "implant.h"
#include "andon.h"
#include "radio.h"
#include "status_led.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef SANDBOX_ONLY

#ifdef IMPLANT_HOST_MOCK
#include "implant_host.h"
/**
 * @brief Read the controllable mock CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (g_mock_implant_dhcsr)
/**
 * @brief Read the mock reserved-sector bot marker.
 */
#define IMPLANT_FLASH_READ() (g_mock_implant_flash)
/**
 * @brief Store the bot marker in the mock reserved sector.
 */
#define IMPLANT_FLASH_WRITE(value) (g_mock_implant_flash = (value))
#else
#include "hardware/flash.h"
#include "hardware/sync.h"
/**
 * @brief Read the real CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (*(volatile uint32_t *)ANDON_IMPLANT_DHCSR_ADDR)
/**
 * @brief Read the real reserved-sector bot marker.
 */
#define IMPLANT_FLASH_READ() (*(volatile uint8_t *)ANDON_IMPLANT_RESERVE_ADDR)
/**
 * @brief Erase and program the reserved-sector bot marker.
 *
 * @param value Marker byte to store in the reserved sector.
 * @return void
 */
static void implant_flash_write(uint8_t value) {
    uint8_t page[FLASH_PAGE_SIZE];
    uint32_t ints = save_and_disable_interrupts();
    memset(page, 0xFF, sizeof(page));
    page[0] = value;
    flash_range_erase(ANDON_IMPLANT_RESERVE_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(ANDON_IMPLANT_RESERVE_OFFSET, page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);
}
/**
 * @brief Write the bot marker into the reserved flash sector.
 */
#define IMPLANT_FLASH_WRITE(value) implant_flash_write(value)
#endif

/**
 * @brief Monotonic implant tick counter.
 */
static uint32_t g_implant_ticks;

/**
 * @brief True when the C2 payload handler has been armed.
 */
static bool g_implant_armed;

/**
 * @brief True when the check-in path is enabled.
 */
static bool g_implant_checkin;

/**
 * @brief True when the remote task handler is enabled.
 */
static bool g_implant_tasking;

/**
 * @brief True once a check-in frame has been emitted.
 */
static bool g_implant_checked_in;

/**
 * @brief Number of benign C2 tasks executed this boot.
 */
static size_t g_implant_task_count;

/**
 * @brief Number of C2 check-ins emitted this boot.
 */
static size_t g_implant_checkin_count;

/**
 * @brief Last benign C2 task code that was executed.
 */
static uint8_t g_implant_last_task;

/**
 * @brief Runtime gate for the C2 check-in path.
 *
 * The corrected build leaves this gate clear, so the node never registers
 * with the local C2 listener.
 */
static volatile bool g_implant_checkin_gate;

/**
 * @brief Runtime gate for the remote task handler.
 *
 * The corrected build leaves this gate clear, so no remotely issued task is
 * ever executed.
 */
static volatile bool g_implant_task_gate;

/**
 * @brief Runtime gate for the reserved-sector bot marker write.
 *
 * The corrected build leaves this gate clear, so no marker is programmed.
 */
static volatile bool g_implant_marker_gate;

/**
 * @brief Build one C2 command frame from the magic, bot id, and task.
 *
 * @param frame Pointer to the ANDON_IMPLANT_TASK_FRAME_LEN output buffer.
 * @param task Benign task code to place in the frame.
 * @return size_t Length in bytes of the built frame.
 */
static size_t implant_build(uint8_t *frame, uint8_t task) {
    memcpy(frame, ANDON_IMPLANT_C2_MAGIC, ANDON_IMPLANT_C2_MAGIC_LEN);
    frame[ANDON_IMPLANT_C2_MAGIC_LEN] = ANDON_IMPLANT_BOT_ID;
    frame[ANDON_IMPLANT_C2_MAGIC_LEN + 1u] = task;
    return ANDON_IMPLANT_TASK_FRAME_LEN;
}

bool implant_debug_attached(void) {
    return (IMPLANT_DHCSR_READ &
            (ANDON_IMPLANT_DHCSR_DEBUGEN | ANDON_IMPLANT_DHCSR_HALT)) != 0u;
}

bool implant_armed(void) {
    return g_implant_armed;
}

bool implant_checked_in(void) {
    return g_implant_checked_in;
}

bool implant_infected(void) {
    return IMPLANT_FLASH_READ() == (uint32_t)ANDON_IMPLANT_MARKER_BYTE;
}

void implant_set_checkin(bool enabled) {
    g_implant_checkin = enabled;
}

void implant_set_tasking(bool enabled) {
    g_implant_tasking = enabled;
}

uint8_t implant_last_task(void) {
    return g_implant_last_task;
}

size_t implant_task_count(void) {
    return g_implant_task_count;
}

size_t implant_checkin_count(void) {
    return g_implant_checkin_count;
}

/**
 * @brief Write the bot marker into the reserved flash sector.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_infect(void) {
    if (!g_implant_marker_gate) {
        return;
    }
    if (implant_infected()) {
        return;
    }
    IMPLANT_FLASH_WRITE((uint32_t)ANDON_IMPLANT_MARKER_BYTE);
}

/**
 * @brief Report whether the implant may check in and run tasks.
 *
 * @param void No parameters.
 * @return bool true when armed, enabled, and unprobed.
 */
static bool implant_ready(void) {
    if (!g_implant_armed || !g_implant_checkin) return false;
    return !implant_debug_attached();
}

/**
 * @brief Report whether a frame carries the C2V1 command magic.
 *
 * @param frame Pointer to the inbound frame bytes.
 * @param len Number of inbound frame bytes.
 * @return bool true when the frame is long enough and matches the magic.
 */
static bool implant_magic_match(const uint8_t *frame, size_t len) {
    if (frame == NULL || len < ANDON_IMPLANT_TASK_FRAME_LEN) return false;
    return memcmp(frame, ANDON_IMPLANT_C2_MAGIC,
                  ANDON_IMPLANT_C2_MAGIC_LEN) == 0;
}

/**
 * @brief Emit one benign C2 status report frame.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_report(void) {
    uint8_t frame[ANDON_IMPLANT_TASK_FRAME_LEN];
    implant_build(frame, ANDON_IMPLANT_TASK_REPORT);
    radio_send_frame(ANDON_UART, frame, sizeof(frame));
}

/**
 * @brief Execute one benign remotely issued C2 task.
 *
 * @param task Benign task code issued by the C2 listener.
 * @return void
 */
static void implant_execute(uint8_t task) {
    if (task == ANDON_IMPLANT_TASK_BLINK) {
        status_led_show(ANDON_ACK_PENDING);
        return;
    }
    if (task == ANDON_IMPLANT_TASK_LOG) {
        printf("C2 log bot=%u\n", (unsigned)ANDON_IMPLANT_BOT_ID);
        return;
    }
    if (task == ANDON_IMPLANT_TASK_REPORT) {
        implant_report();
    }
}

/**
 * @brief Emit one C2 check-in frame and record the registration.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_emit_checkin(void) {
    uint8_t frame[ANDON_IMPLANT_TASK_FRAME_LEN];
    implant_build(frame, 0u);
    radio_send_frame(ANDON_UART, frame, sizeof(frame));
    g_implant_checked_in = true;
    g_implant_checkin_count += 1u;
}

bool implant_check_in(void) {
    if (!g_implant_checkin_gate) {
        return false;
    }
    if (!implant_ready()) {
        return false;
    }
    implant_emit_checkin();
    return true;
}

/**
 * @brief Validate a C2 tasking frame and recover its task byte.
 *
 * @param frame Pointer to the inbound frame bytes.
 * @param len Number of inbound frame bytes.
 * @param task Pointer to store the recovered task byte.
 * @return bool true when the frame is an authorized C2 task.
 */
static bool implant_tasking_frame(const uint8_t *frame, size_t len,
                                  uint8_t *task) {
    if (!g_implant_task_gate) return false;
    if (!g_implant_tasking) return false;
    if (implant_debug_attached()) return false;
    if (!implant_magic_match(frame, len)) return false;
    *task = frame[ANDON_IMPLANT_C2_MAGIC_LEN + 1u];
    return true;
}

void implant_handle_command(const uint8_t *frame, size_t len) {
    uint8_t task;
    if (!implant_tasking_frame(frame, len, &task)) {
        return;
    }
    g_implant_armed = true;
    implant_infect();
    g_implant_last_task = task;
    g_implant_task_count += 1u;
    implant_execute(task);
}

/**
 * @brief Clear every implant action gate to its corrected state.
 *
 * The corrected build starts with each gate clear, so the C2 check-in, the
 * remote task handler, and the marker write all stay inert until a defect is
 * introduced into the image.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_reset_gates(void) {
    g_implant_checkin_gate = false;
    g_implant_task_gate = false;
    g_implant_marker_gate = false;
}

/**
 * @brief Reset every implant runtime flag and counter.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_reset_state(void) {
    g_implant_ticks = 0u;
    g_implant_armed = false;
    g_implant_checkin = true;
    g_implant_tasking = true;
    g_implant_checked_in = false;
    g_implant_task_count = 0u;
    g_implant_checkin_count = 0u;
    g_implant_last_task = 0u;
}

void implant_init(void) {
    implant_reset_gates();
    implant_reset_state();
    if (implant_infected()) {
        g_implant_armed = true;
        return;
    }
    implant_infect();
}

void implant_tick(void) {
    g_implant_ticks += 1u;
    if (!g_implant_armed) return;
    if ((g_implant_ticks % ANDON_IMPLANT_TICK_INTERVAL) != 0u) return;
    implant_check_in();
}

void implant_neutralize(void) {
    g_implant_checkin = false;
    g_implant_tasking = false;
    g_implant_armed = false;
    g_implant_checked_in = false;
    IMPLANT_FLASH_WRITE(0u);
}

#endif // SANDBOX_ONLY
