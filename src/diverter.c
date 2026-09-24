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
// File:    diverter.c
// Desc:    Implements the line diverter state machine that sequences the
//          SG90 actuator and moves to the divert posture on loss of
//          authority.
// Created: 2026

#include "pico/time.h"
#include "diverter.h"
#include "servo.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Current diverter gate position and health state.
 */
static diverter_state_t g_diverter_state;

/**
 * @brief Pending travel target, true when the gate is deploying.
 */
static bool g_diverter_target_deploy;

/**
 * @brief Absolute time in microseconds when the pending travel completes.
 */
static uint64_t g_diverter_move_until_us;

/**
 * @brief Complete a pending travel by driving the diverter actuator.
 *
 * @param void No parameters.
 * @return void
 */
static void diverter_complete(void) {
    if (g_diverter_target_deploy) {
        diverter_deploy();
        g_diverter_state = DIVERTER_STATE_DEPLOYED;
        return;
    }
    diverter_retract();
    g_diverter_state = DIVERTER_STATE_RETRACTED;
}

void diverter_init(void) {
    g_diverter_target_deploy = false;
    g_diverter_state = DIVERTER_STATE_RETRACTED;
    diverter_retract();
}

diverter_state_t diverter_state(void) {
    return g_diverter_state;
}

bool diverter_is_deployed(void) {
    return g_diverter_state == DIVERTER_STATE_DEPLOYED;
}

void diverter_apply_command(bool deploy, bool authorized) {
    if (!authorized) {
        return;
    }
    g_diverter_target_deploy = deploy;
    g_diverter_state = DIVERTER_STATE_MOVING;
    g_diverter_move_until_us =
        time_us_64() + (uint64_t)DIVERTER_TRAVEL_MS * 1000u;
}

void diverter_tick(void) {
    if (g_diverter_state != DIVERTER_STATE_MOVING) {
        return;
    }
    if (time_us_64() < g_diverter_move_until_us) {
        return;
    }
    diverter_complete();
}

void diverter_fail_safe(void) {
    diverter_deploy();
    g_diverter_target_deploy = true;
    g_diverter_state = DIVERTER_STATE_FAULT;
}
