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
// File:    andon.h
// Desc:    Declares platform pin mapping, peripheral handles, and
//          provisioning boundaries for the IRON CHOIR factory andon
//          station node.
// Created: 2026

#ifndef ANDON_H
#define ANDON_H

#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "packet_artifact.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Onboard heartbeat LED GPIO pin number.
 */
#define ANDON_LED_PIN 25u

/**
 * @brief DHT11 line temperature sensor GPIO pin number.
 */
#define ANDON_DHT_PIN 4u

/**
 * @brief I2C peripheral used by the 1602 LCD backpack.
 */
#define ANDON_I2C i2c1

/**
 * @brief I2C SDA GPIO pin number.
 */
#define ANDON_I2C_SDA 2u

/**
 * @brief I2C SCL GPIO pin number.
 */
#define ANDON_I2C_SCL 3u

/**
 * @brief I2C bus clock rate in hertz.
 */
#define ANDON_I2C_BAUD 100000u

/**
 * @brief I2C address of the 1602 LCD PCF8574 backpack.
 */
#define ANDON_LCD_ADDR PACKET_LCD_I2C_ADDRESS

/**
 * @brief UART peripheral used by the RYLR998 transceiver.
 */
#define ANDON_UART uart1

/**
 * @brief UART TX GPIO pin number to the RYLR998 RX input.
 */
#define ANDON_UART_TX 8u

/**
 * @brief UART RX GPIO pin number from the RYLR998 TX output.
 */
#define ANDON_UART_RX 9u

/**
 * @brief UART baud rate negotiated with the RYLR998.
 */
#define ANDON_UART_BAUD 115200u

/**
 * @brief RYLR998 network identifier shared by all classroom radios.
 */
#define ANDON_NETWORK_ID 18u

/**
 * @brief Fixed andon frame size in bytes.
 */
#define ANDON_FRAME_SIZE PACKET_FRAME_SIZE

/**
 * @brief Time to wait for a sealed fault command before failing safe.
 */
#define ANDON_LINK_WAIT_MS PACKET_LINK_WAIT_MS

/**
 * @brief Servo pulse width in microseconds that deploys the line diverter.
 */
#define ANDON_DIVERTER_DEPLOY_PULSE_US PACKET_DIVERTER_DEPLOY_PULSE_US

/**
 * @brief Servo pulse width in microseconds that retracts the line diverter.
 */
#define ANDON_DIVERTER_RETRACT_PULSE_US PACKET_DIVERTER_RETRACT_PULSE_US

/**
 * @brief Red FAULT tower light GPIO pin number.
 */
#define ANDON_RED_LED_PIN 16u

/**
 * @brief Yellow ACK PENDING tower light GPIO pin number.
 */
#define ANDON_YELLOW_LED_PIN 17u

/**
 * @brief Green LINE OK tower light GPIO pin number.
 */
#define ANDON_GREEN_LED_PIN 18u

/**
 * @brief Fault-clear push-button GPIO pin number.
 */
#define ANDON_BUTTON_PIN 15u

/**
 * @brief Line diverter actuator servo PWM GPIO pin number.
 */
#define ANDON_SERVO_PIN 14u

/**
 * @brief Infrared receiver GPIO pin number.
 */
#define ANDON_IR_PIN 5u

/**
 * @brief Lowest acceptable line temperature in tenths of a degree.
 */
#define ANDON_TEMP_MIN_TENTHS 0

/**
 * @brief Highest acceptable line temperature in tenths of a degree.
 */
#define ANDON_TEMP_MAX_TENTHS 400

/**
 * @brief Lowest accepted production line zone identifier.
 */
#define ANDON_ZONE_MIN 0

/**
 * @brief Highest accepted production line zone identifier.
 */
#define ANDON_ZONE_MAX 16

/**
 * @brief Provisioned andon station node identifier.
 */
#define ANDON_NODE_ID PACKET_NODE_ADDRESS

/**
 * @brief Provisioned factory control gateway LoRa address.
 */
#define ANDON_GATEWAY_ADDRESS PACKET_GATEWAY_ADDRESS

#endif // ANDON_H
