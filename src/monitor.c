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
// File:    monitor.c
// Desc:    Implements the andon station state machine that ties the local
//          fault-clear remote, the sealed fault command path, the line
//          temperature sensor, the line diverter, and the RYLR998
//          factory control link together. The production build never
//          applies an untrusted frame and never executes a remotely issued
//          task: the SANDBOX_ONLY implant is the only covert path and it
//          is compiled out of the clean build.
// Created: 2026

#include "andon.h"
#include "monitor.h"
#include "sensor.h"
#include "display.h"
#include "radio.h"
#include "status_led.h"
#include "button.h"
#include "servo.h"
#include "ir_remote.h"
#include "diverter.h"
#include "control.h"
#include "implant.h"
#include "crypto_aead.h"
#include "crypto_kdf.h"
#include "field_secrets.h"
#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "pico/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Guarded andon states derived from authorized fault commands.
 */
typedef enum andon_state {
    /**
     * @brief Line is running clear and the diverter is retracted.
     */
    ANDON_STATE_LINE_OK = 0,
    /**
     * @brief A fault clear is pending authorization.
     */
    ANDON_STATE_ACK_PENDING = 1,
    /**
     * @brief An authorized fault is active and the diverter is deployed.
     */
    ANDON_STATE_FAULT = 2,
    /**
     * @brief The control link was lost or a command was rejected.
     */
    ANDON_STATE_DENIED = 3,
} andon_state_t;

/**
 * @brief Module-ready flag.
 */
static bool g_ready;

/**
 * @brief Initialized I2C peripheral handle for the LCD backpack.
 */
static i2c_inst_t *g_i2c;

/**
 * @brief Initialized I2C backpack address for the LCD.
 */
static uint8_t g_i2c_addr;

/**
 * @brief Derived XChaCha20-Poly1305 field key for the control link.
 */
static uint8_t g_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been derived and installed.
 */
static bool g_key_ready;

/**
 * @brief True once a sealed fault command has been accepted.
 */
static bool g_link_seen;

/**
 * @brief Absolute time in microseconds of the last accepted command.
 */
static uint64_t g_last_rx_us;

/**
 * @brief Last observed line temperature in-range verdict.
 */
static bool g_temp_ok;

/**
 * @brief Last observed line temperature in tenths of a degree Celsius.
 */
static int16_t g_temp_tenths;

/**
 * @brief Guarded andon state.
 */
static andon_state_t g_state;

/**
 * @brief Line zone recovered from the last accepted command.
 */
static int16_t g_zone;

/**
 * @brief True while a local fault clear awaits authorization.
 */
static bool g_clear_pending;

/**
 * @brief First LCD andon render line buffer.
 */
static char g_line1[DISPLAY_LINE_LEN];

/**
 * @brief Second LCD andon render line buffer.
 */
static char g_line2[DISPLAY_LINE_LEN];

/**
 * @brief Inbound radio line accumulator.
 */
static char g_rx_line[RADIO_LINE_BUF_LEN];

/**
 * @brief Number of bytes currently held in the inbound line accumulator.
 */
static size_t g_rx_len;

/**
 * @brief Live console reading sequence number.
 */
static uint16_t g_seq;

/**
 * @brief Probe one I2C address and report whether it acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to probe.
 * @param addr The 7-bit address to probe.
 * @return bool true when the address acknowledged.
 */
static bool i2c_probe(i2c_inst_t *i2c, uint8_t addr) {
    uint8_t dummy = 0u;
    if (i2c_write_blocking(i2c, addr, &dummy, 1u, false) < 0) {
        return false;
    }
    printf("  found 0x%02X\n", (unsigned)addr);
    return true;
}

/**
 * @brief Probe the I2C bus and print every device that acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to scan.
 * @return void
 */
static void i2c_bus_scan(i2c_inst_t *i2c) {
    uint8_t addr;
    uint8_t found = 0u;
    printf("I2C scan:\n");
    for (addr = 0x08u; addr < 0x78u; ++addr) {
        found += i2c_probe(i2c, addr) ? 1u : 0u;
    }
    if (found == 0u) {
        printf("  no devices\n");
    }
}

/**
 * @brief Initialize the I2C bus pins and scan the bus.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_bus_init(void) {
    i2c_init(ANDON_I2C, ANDON_I2C_BAUD);
    gpio_set_function(ANDON_I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(ANDON_I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(ANDON_I2C_SDA);
    gpio_pull_up(ANDON_I2C_SCL);
    i2c_bus_scan(ANDON_I2C);
}

/**
 * @brief Configure the onboard heartbeat LED.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_gpio_init(void) {
    gpio_init(ANDON_LED_PIN);
    gpio_set_dir(ANDON_LED_PIN, GPIO_OUT);
    gpio_put(ANDON_LED_PIN, 0);
}

/**
 * @brief Pulse the onboard GP25 heartbeat LED once.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_heartbeat(void) {
    gpio_put(ANDON_LED_PIN, 1);
    sleep_us(MONITOR_HEARTBEAT_US);
    gpio_put(ANDON_LED_PIN, 0);
}

/**
 * @brief Clear every latched andon state flag.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_clear_state(void) {
    g_link_seen = false;
    g_last_rx_us = 0u;
    g_temp_ok = false;
    g_temp_tenths = 0;
    g_state = ANDON_STATE_LINE_OK;
    g_zone = 0;
    g_clear_pending = false;
}

/**
 * @brief Drive the line diverter for the current guarded andon state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_apply_state(void) {
    bool deploy = (g_state == ANDON_STATE_FAULT) ||
                  (g_state == ANDON_STATE_DENIED);
    diverter_apply_command(deploy, true);
}

/**
 * @brief Initialize the LED, LCD handles, diverter, and andon state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init(void) {
    monitor_gpio_init();
    g_i2c = ANDON_I2C;
    g_i2c_addr = ANDON_LCD_ADDR;
    monitor_clear_state();
    diverter_init();
    monitor_apply_state();
    g_ready = true;
}

/**
 * @brief Initialize the human interface and actuator peripherals.
 *
 * @param void No parameters.
 * @return bool true when the LEDs, button, servo, and infrared eye ready.
 */
static bool monitor_peripherals_init(void) {
    return status_led_init() && clear_init() && servo_init() &&
           ir_remote_init();
}

/**
 * @brief Initialize the SANDBOX_ONLY implant when it is compiled in.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_implant_init(void) {
#ifdef SANDBOX_ONLY
    implant_init();
#endif
}

/**
 * @brief Derive the field key from the committed lab secret.
 *
 * LAB-ONLY: production must provision the field key through OTP rather
 * than deriving it from a committed passphrase and salt.
 *
 * @param void No parameters.
 * @return bool true when the field key was derived and installed.
 */
static bool monitor_derive_key(void) {
    bool ok = crypto_kdf_argon2id((const uint8_t *)FIELD_SECRET_PASSPHRASE,
                                  strlen(FIELD_SECRET_PASSPHRASE),
                                  FIELD_SECRET_SALT, 16u, g_key);
    g_key_ready = ok;
    control_set_key(ok ? g_key : NULL);
    return ok;
}

/**
 * @brief Print the boot banner and the control hint for the console.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_console_banner(void) {
    printf("=== OPERATION IRON CHOIR // ACT VII ANDON LINE ===\n");
    printf("REMOTE: CH+ 0x47=FAULT_CLEAR CH- 0x45=TEST CH 0x46=ACK\n");
    printf("BUTTON GP15: local fault clear (needs authorization)\n");
}

/**
 * @brief Bring up the andon state and command path.
 *
 * @param void No parameters.
 * @return bool true when the field key was installed.
 */
static bool monitor_start(void) {
    bool ok;
    monitor_state_init();
    control_init();
    monitor_implant_init();
    ok = monitor_derive_key();
    if (ok) monitor_console_banner();
    return ok;
}

bool monitor_init(void) {
    monitor_bus_init();
    if (!monitor_peripherals_init() || !sensor_init() ||
        !radio_init(ANDON_UART) ||
        !display_init(ANDON_I2C, ANDON_LCD_ADDR)) {
        printf("INIT FAIL\n");
        return false;
    }
    return monitor_start();
}

void monitor_deinit(void) {
    g_ready = false;
    control_deinit();
}

void monitor_clear_request(void) {
    g_clear_pending = false;
}

/**
 * @brief Map an authorized command byte to the guarded andon state.
 *
 * @param command Guarded andon command code.
 * @return andon_state_t Guarded andon state for the command.
 */
static andon_state_t monitor_state_for(uint8_t command) {
    if (command == ANDON_COMMAND_FAULT) return ANDON_STATE_FAULT;
    if (command == ANDON_COMMAND_CLEAR) return ANDON_STATE_LINE_OK;
    if (command == ANDON_COMMAND_ACK) return ANDON_STATE_ACK_PENDING;
    return ANDON_STATE_DENIED;
}

/**
 * @brief Map a guarded andon state to its tower light lamp.
 *
 * @param state Guarded andon state to map.
 * @return andon_led_state_t Tower light state for the andon state.
 */
static andon_led_state_t monitor_led_for(andon_state_t state) {
    if (state == ANDON_STATE_DENIED) return ANDON_FAULT;
    if (state == ANDON_STATE_FAULT) {
        return g_clear_pending ? ANDON_ACK_PENDING : ANDON_FAULT;
    }
    if (state == ANDON_STATE_ACK_PENDING) return ANDON_ACK_PENDING;
    return g_clear_pending ? ANDON_ACK_PENDING : ANDON_LINE_OK;
}

/**
 * @brief Render a guarded andon state as a short status label.
 *
 * @param state Guarded andon state to render.
 * @return const char* NUL-terminated state label.
 */
static const char *monitor_state_text(andon_state_t state) {
    if (state == ANDON_STATE_LINE_OK) return "OK";
    if (state == ANDON_STATE_ACK_PENDING) return "ACK";
    if (state == ANDON_STATE_FAULT) return "FAULT";
    return "DENY";
}

/**
 * @brief Render the control link status as a short label.
 *
 * @param void No parameters.
 * @return const char* NUL-terminated link label.
 */
static const char *monitor_link_text(void) {
    return g_link_seen ? "UP" : "--";
}

/**
 * @brief Render the resistance, masked by the SANDBOX_ONLY infection.
 *
 * @param void No parameters.
 * @return const char* NUL-terminated infection label.
 */
static const char *monitor_infection_text(void) {
#ifdef SANDBOX_ONLY
    return implant_infected() ? "INF" : "--";
#else
    return "--";
#endif
}

/**
 * @brief Format the active line zone as a short decimal text.
 *
 * @param out Pointer to the mutable text buffer.
 * @param out_len Capacity of the text buffer in bytes.
 * @return void
 */
static void monitor_zone_text(char *out, size_t out_len) {
    snprintf(out, out_len, "%d", (int)g_zone);
}

/**
 * @brief Format the line temperature as a short decimal text.
 *
 * @param out Pointer to the mutable text buffer.
 * @param out_len Capacity of the text buffer in bytes.
 * @return void
 */
static void monitor_temp_text(char *out, size_t out_len) {
    snprintf(out, out_len, "%d", (int)g_temp_tenths);
}

/**
 * @brief Map a tower light lamp state to a short text label.
 *
 * @param state Tower light lamp state to map.
 * @return const char* NUL-terminated lamp label.
 */
static const char *monitor_led_text(andon_led_state_t state) {
    if (state == ANDON_ACK_PENDING) return "YELLOW";
    if (state == ANDON_FAULT) return "RED";
    return (state == ANDON_LINE_OK) ? "GREEN" : "OFF";
}

/**
 * @brief Print one live status line for the interactive console.
 *
 * @param reading Pointer to the decoded DHT11 reading.
 * @return void
 */
static void monitor_log_reading(const dht_reading_t *reading) {
    andon_led_state_t led = monitor_led_for(g_state);
    printf("CLIMATE t=%d ok=%d ST=%s LED=%s seq=%u\n",
           (int)reading->temperature_tenths, (int)g_temp_ok,
           monitor_state_text(g_state), monitor_led_text(led),
           (unsigned)g_seq);
    g_seq += 1u;
}

/**
 * @brief Print the live sensor failure line and mark the line temp invalid.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_climate_fail(void) {
    g_temp_ok = false;
    printf("SENSOR read failed -> WARNING\n");
}

/**
 * @brief Format the andon status and zone lines into the render buffers.
 *
 * @param zone Pointer to the formatted zone text.
 * @param temp Pointer to the formatted temperature text.
 * @return void
 */
static void monitor_format_lines(const char *zone, const char *temp) {
    snprintf(g_line1, DISPLAY_LINE_LEN, "ST:%-5s L:%s",
             monitor_state_text(g_state), monitor_link_text());
    snprintf(g_line2, DISPLAY_LINE_LEN, "Z:%s T:%s I:%s",
             zone, temp, monitor_infection_text());
}

/**
 * @brief Render the andon status and zone lines to the 1602 LCD.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_render(void) {
    char zone[8];
    char temp[8];
    monitor_zone_text(zone, sizeof(zone));
    monitor_temp_text(temp, sizeof(temp));
    monitor_format_lines(zone, temp);
    display_render_lines(g_i2c, g_i2c_addr, g_line1, g_line2);
}

/**
 * @brief Sample the DHT11 line sensor and classify it.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_refresh_temp(void) {
    dht_reading_t reading;
    if (sensor_read(&reading) != SENSOR_RESULT_OK) {
        monitor_climate_fail();
        return;
    }
    g_temp_ok = line_temp_ok(&reading);
    g_temp_tenths = reading.temperature_tenths;
    monitor_log_reading(&reading);
}

/**
 * @brief Consume one debounced fault-clear press and raise the request.
 *
 * A local fault clear raises the ACK PENDING indication. It never
 * changes the guarded state on its own, so it cannot silently bypass
 * authorization.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_clear(void) {
    if (!clear_consume_press()) {
        return;
    }
    g_clear_pending = true;
    printf("BUTTON fault clear -> pending authorization\n");
}

/**
 * @brief Apply one decoded infrared fault-clear remote command.
 *
 * @param cmd Pointer to the decoded infrared command.
 * @return void
 */
static void monitor_apply_ir_command(const ir_command_t *cmd) {
    if (cmd->command == ANDON_IR_TEST) {
        return;
    }
    if (cmd->command == ANDON_IR_FAULT_CLEAR ||
        cmd->command == ANDON_IR_ACK) {
        g_clear_pending = true;
    }
}

/**
 * @brief Map a decoded remote command to its name.
 *
 * @param command Decoded NEC command byte.
 * @return const char* Command name string.
 */
static const char *monitor_ir_name(uint8_t command) {
    if (command == ANDON_IR_FAULT_CLEAR) return "FAULT_CLEAR";
    if (command == ANDON_IR_ACK) return "ACK";
    return (command == ANDON_IR_TEST) ? "TEST" : "UNKNOWN";
}

/**
 * @brief Poll the infrared fault-clear remote for a command.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_ir(void) {
    ir_command_t cmd;
    if (!ir_remote_poll(&cmd)) {
        return;
    }
    printf("%s (0x%02X)\n", monitor_ir_name(cmd.command),
           (unsigned)cmd.command);
    monitor_apply_ir_command(&cmd);
}

/**
 * @brief Apply one authorized command to the diverter and andon state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_apply_command(void) {
    g_state = monitor_state_for(control_command());
    g_zone = (int16_t)control_zone();
    g_clear_pending = false;
    monitor_apply_state();
}

/**
 * @brief Feed an inbound frame to the SANDBOX_ONLY implant when compiled in.
 *
 * The production firmware compiles this path out, so an untrusted frame
 * can never trigger a covert exchange or a remotely issued task.
 *
 * @param hex Pointer to the inbound frame text.
 * @param len Number of inbound frame bytes.
 * @return void
 */
static void monitor_implant_frame(const char *hex, size_t len) {
#ifdef SANDBOX_ONLY
    implant_handle_command((const uint8_t *)hex, len);
#else
    (void)hex;
    (void)len;
#endif
}

/**
 * @brief Verify and apply one inbound andon frame.
 *
 * The sealed fault or clear command is authenticated and authorized
 * before it can move the diverter. No local fault clear can bypass this
 * authorization, and no untrusted task is ever executed.
 *
 * @param hex Pointer to the inbound frame text.
 * @param len Number of inbound frame bytes.
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_apply_frame(const char *hex, size_t len, uint64_t now_us) {
    monitor_implant_frame(hex, len);
    if (!control_handle_frame(hex)) {
        return;
    }
    g_link_seen = true;
    g_last_rx_us = now_us;
    monitor_apply_command();
}

/**
 * @brief Fail safe to the divert posture on a silent control link.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_fail_safe(void) {
    g_state = ANDON_STATE_DENIED;
    g_zone = 0;
    g_clear_pending = false;
    diverter_fail_safe();
}

/**
 * @brief Drain inbound radio lines and apply any sealed command.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_rx_tick(uint64_t now_us) {
    radio_rcv_t rcv;
    while (radio_line_pump(ANDON_UART, g_rx_line, &g_rx_len)) {
        if (radio_parse_rcv(g_rx_line, &rcv) == RADIO_RESULT_OK) {
            printf("RX from 0x%04X, %u bytes\n", (unsigned)rcv.sender,
                   (unsigned)rcv.len);
            monitor_apply_frame(rcv.payload, rcv.len, now_us);
        }
    }
}

/**
 * @brief Drive to the fail-safe posture when the control link goes silent.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_check_link(uint64_t now_us) {
    if (!g_link_seen) {
        return;
    }
    if ((now_us - g_last_rx_us) <= (uint64_t)ANDON_LINK_WAIT_MS * 1000u) {
        return;
    }
    monitor_fail_safe();
}

/**
 * @brief Service the clear button, fault-clear remote, and control link.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_service_inputs(uint64_t now_us) {
    monitor_handle_clear();
    monitor_handle_ir();
    monitor_rx_tick(now_us);
    monitor_check_link(now_us);
}

/**
 * @brief Advance the SANDBOX_ONLY implant when it is compiled in.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_implant_tick(void) {
#ifdef SANDBOX_ONLY
    implant_tick();
#endif
}

/**
 * @brief Drive exactly one tower light lamp for the current andon state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_drive_leds(void) {
    status_led_show(monitor_led_for(g_state));
}

/**
 * @brief Drive the tower light, diverter, implant, and andon display.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_service_outputs(void) {
    monitor_implant_tick();
    diverter_tick();
    monitor_drive_leds();
    monitor_render();
    monitor_heartbeat();
}

bool monitor_step(void) {
    uint64_t now_us;
    if (!g_ready) {
        return false;
    }
    now_us = time_us_64();
    monitor_refresh_temp();
    monitor_service_inputs(now_us);
    monitor_service_outputs();
    return true;
}
