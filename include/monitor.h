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
// File:    monitor.h
// Desc:    Declares the andon station state machine tying the local
//          fault-clear remote, the sealed fault command path, the line
//          temperature sensor, the line diverter, and the factory
//          control gateway link together.
// Created: 2026

#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Onboard GP25 heartbeat pulse width in microseconds.
 */
#define MONITOR_HEARTBEAT_US 1000u

/**
 * @brief Infrared remote code that requests a line fault clear.
 *
 * An operator points the local remote at the andon station and presses
 * CLEAR to request that a fault be cleared. The code is read from the
 * wire with no challenge and no secret, so it can never clear a fault by
 * itself: it only raises an ACK PENDING indication. A sealed clear
 * command from the authorized control gateway is still required.
 */
#define ANDON_IR_FAULT_CLEAR 0x47u

/**
 * @brief Infrared remote code that acknowledges a line fault.
 *
 * The ACK code tells the andon station that an operator has seen the
 * fault. It is also unauthenticated and only raises the ACK PENDING
 * indication; it changes no guarded state on its own.
 */
#define ANDON_IR_ACK 0x46u

/**
 * @brief Infrared remote code that exercises the tower light lamps.
 *
 * The TEST code is a lamp check used during shift handover. It is
 * unauthenticated and touches no guarded state.
 */
#define ANDON_IR_TEST 0x45u

/**
 * @brief Initialize the andon station state machine.
 *
 * Configures the I2C LCD, the DHT11 line temperature sensor, the
 * infrared fault-clear remote, the tower light lamps, the line diverter
 * servo, the fault-clear button, the RYLR998 radio, and derives the
 * Argon2id field key.
 *
 * @param void No parameters.
 * @return bool true when all submodules initialized.
 */
bool monitor_init(void);

/**
 * @brief Clear the node-ready flag and command path.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_deinit(void);

/**
 * @brief Clear a pending local fault-clear request.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_clear_request(void);

/**
 * @brief Execute one andon station tick.
 *
 * Polls the fault-clear remote and the radio, verifies and applies sealed
 * fault and clear commands, drives the diverter and tower light, renders
 * the andon status, and fails safe to the divert posture on a lost
 * control link. A local clear never bypasses authorization and untrusted
 * frames are never applied.
 *
 * @param void No parameters.
 * @return bool true when the tick completed without a policy error.
 */
bool monitor_step(void);

#endif // MONITOR_H
