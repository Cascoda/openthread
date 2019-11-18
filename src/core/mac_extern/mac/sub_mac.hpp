/*
 *  Copyright (c) 2016-2018, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file includes definitions for the IEEE 802.15.4 MAC layer (sub-MAC).
 */

#ifndef SUB_MAC_HPP_
#define SUB_MAC_HPP_

#include "openthread-core-config.h"

#include <openthread/link.h>

#include "common/locator.hpp"
#include "common/timer.hpp"
#include "mac/mac_frame.hpp"
#include "radio/radio.hpp"

namespace ot {

/**
 * @addtogroup core-mac
 *
 * @brief
 *   This module includes definitions for the IEEE 802.15.4 MAC (sub-MAC).
 *
 * @{
 *
 */

namespace Mac {

/**
 * This class implements the IEEE 802.15.4 MAC (sub-MAC).
 *
 * Sub-MAC layer implements a subset of IEEE802.15.4 MAC primitives which are shared by both MAC layer (in FTD/MTD
 * modes) and Raw Link (Radio only mode).

 * The sub-MAC layer handles the following (if not provided by radio platform):
 *
 *    - Ack timeout for frame transmission,
 *    - CSMA backoff logic,
 *    - Frame re-transmissions,
 *    - Energy scan on a single channel and RSSI sampling.
 *
 * It also act as the interface (to radio platform) for setting/getting radio configurations such as short or extended
 * addresses and PAN Id.
 *
 */
class SubMac : public InstanceLocator
{
    friend class Radio::Callbacks;

public:
    enum
    {
        kInvalidRssiValue = 127, ///< Invalid Received Signal Strength Indicator (RSSI) value.
    };

    /**
     * This constructor initializes the `SubMac` object.
     *
     * @param[in]  aInstance  A reference to the OpenThread instance.
     *
     */
    explicit SubMac(Instance &aInstance);

private:
    enum
    {
        kMinBE             = 3,  ///< macMinBE (IEEE 802.15.4-2006).
        kMaxBE             = 5,  ///< macMaxBE (IEEE 802.15.4-2006).
        kUnitBackoffPeriod = 20, ///< Number of symbols (IEEE 802.15.4-2006).
        kMinBackoff        = 1,  ///< Minimum backoff (milliseconds).
        kAckTimeout        = 16, ///< Timeout for waiting on an ACK (milliseconds).

#if OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE
        kEnergyScanRssiSampleInterval = 128, ///< RSSI sample interval during energy scan, 128 usec
#else
        kEnergyScanRssiSampleInterval = 1, ///< RSSI sample interval during energy scan, 1 ms
#endif
    };

    enum State
    {
        kStateDisabled,    ///< Radio is disabled.
        kStateSleep,       ///< Radio is in sleep.
        kStateReceive,     ///< Radio in in receive.
        kStateCsmaBackoff, ///< CSMA backoff before transmission.
        kStateTransmit,    ///< Radio is transmitting.
        kStateEnergyScan,  ///< Energy scan.
    };
};

/**
 * @}
 *
 */

} // namespace Mac
} // namespace ot

#endif // SUB_MAC_HPP_
