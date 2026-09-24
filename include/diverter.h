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
// File:    diverter.h
// Desc:    Declares the line diverter state machine that sequences the
//          SG90 actuator and moves to the divert posture on loss of
//          authority.
// Created: 2026

#ifndef DIVERTER_H
#define DIVERTER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Bounded diverter gate travel time in milliseconds.
 */
#define DIVERTER_TRAVEL_MS 1000u

/**
 * @brief Diverter gate position and health states.
 */
typedef enum diverter_state {
    /**
     * @brief Gate is retracted, the line runs clear.
     */
    DIVERTER_STATE_RETRACTED = 0,
    /**
     * @brief Gate is deployed to divert a faulted product.
     */
    DIVERTER_STATE_DEPLOYED = 1,
    /**
     * @brief Gate has failed safe into the divert posture.
     */
    DIVERTER_STATE_FAULT = 2,
    /**
     * @brief Gate actuator is travelling between positions.
     */
    DIVERTER_STATE_MOVING = 3,
} diverter_state_t;

/**
 * @brief Initialize the diverter state machine and retract the gate.
 *
 * @param void No parameters.
 * @return void
 */
void diverter_init(void);

/**
 * @brief Return the current diverter state.
 *
 * @param void No parameters.
 * @return diverter_state_t Current diverter state.
 */
diverter_state_t diverter_state(void);

/**
 * @brief Report whether the gate is currently fully deployed.
 *
 * @param void No parameters.
 * @return bool true when the gate is deployed.
 */
bool diverter_is_deployed(void);

/**
 * @brief Apply an authorized deploy or retract command to the gate.
 *
 * Unauthorized commands are refused. An authorized command starts a
 * bounded travel interval that diverter_tick completes. This is the
 * guarded command path that prevents an unauthenticated local clear from
 * moving the gate.
 *
 * @param deploy True to drive the gate deployed, false to retract it.
 * @param authorized True when the caller has validated the command.
 * @return void
 */
void diverter_apply_command(bool deploy, bool authorized);

/**
 * @brief Advance the diverter state machine by one tick.
 *
 * Completes a pending travel once the bounded interval has elapsed.
 *
 * @param void No parameters.
 * @return void
 */
void diverter_tick(void);

/**
 * @brief Force the gate into the divert posture and record the fault.
 *
 * This is the fail-safe posture taken when the andon link is lost or a
 * fault frame cannot be authorized.
 *
 * @param void No parameters.
 * @return void
 */
void diverter_fail_safe(void);

#endif // DIVERTER_H
