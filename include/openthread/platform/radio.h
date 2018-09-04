/*
 *  Copyright (c) 2016, The OpenThread Authors.
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
 * @brief
 *   This file defines the radio interface for OpenThread.
 *
 */

#ifndef OPENTHREAD_PLATFORM_RADIO_H_
#define OPENTHREAD_PLATFORM_RADIO_H_

#include <stdint.h>

#include <openthread/error.h>
#include <openthread/instance.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup plat-radio
 *
 * @brief
 *   This module includes the platform abstraction for radio communication.
 *
 * @{
 *
 */

/**
 * @defgroup radio-types Types
 *
 * @brief
 *   This module includes the platform abstraction for a radio frame.
 *
 * @{
 *
 */

enum
{
    OT_RADIO_FRAME_MAX_SIZE     = 127,    ///< aMaxPHYPacketSize (IEEE 802.15.4-2006)
    OT_RADIO_MSDU_MAX_SIZE      = 118,    ///< aMaxMACPayloadSize (IEEE 802.15.4-2006)
    OT_RADIO_BEACON_MAX_PAYLOAD = 52,     ///< aMaxBeaconPayloadLength (IEEE 802.15.4-2006)
    OT_RADIO_SYMBOLS_PER_OCTET  = 2,      ///< 2.4 GHz IEEE 802.15.4-2006
    OT_RADIO_BIT_RATE           = 250000, ///< 2.4 GHz IEEE 802.15.4 (bits per second)
    OT_RADIO_BITS_PER_OCTET     = 8,      ///< Number of bits per octet

    OT_RADIO_SYMBOL_TIME  = ((OT_RADIO_BITS_PER_OCTET / OT_RADIO_SYMBOLS_PER_OCTET) * 1000000) / OT_RADIO_BIT_RATE,
    OT_RADIO_LQI_NONE     = 0,   ///< LQI measurement not supported
    OT_RADIO_RSSI_INVALID = 127, ///< Invalid or unknown RSSI value
};

/**
 * This enumeration defines the channel page.
 *
 */
enum
{
    OT_RADIO_CHANNEL_PAGE_0      = 0,                               ///< 2.4 GHz IEEE 802.15.4-2006
    OT_RADIO_CHANNEL_PAGE_0_MASK = (1U << OT_RADIO_CHANNEL_PAGE_0), ///< 2.4 GHz IEEE 802.15.4-2006
    OT_RADIO_CHANNEL_PAGE_2      = 2,                               ///< 915 MHz IEEE 802.15.4-2006
    OT_RADIO_CHANNEL_PAGE_2_MASK = (1U << OT_RADIO_CHANNEL_PAGE_2), ///< 915 MHz IEEE 802.15.4-2006
    OT_RADIO_CHANNEL_PAGE_MAX    = OT_RADIO_CHANNEL_PAGE_2,         ///< Maximum supported channel page value
};

/**
 * This enumeration defines the frequency band channel range.
 *
 */
enum
{
    OT_RADIO_915MHZ_OQPSK_CHANNEL_MIN  = 1,                                           ///< 915 MHz IEEE 802.15.4-2006
    OT_RADIO_915MHZ_OQPSK_CHANNEL_MAX  = 10,                                          ///< 915 MHz IEEE 802.15.4-2006
    OT_RADIO_915MHZ_OQPSK_CHANNEL_MASK = 0x3ff << OT_RADIO_915MHZ_OQPSK_CHANNEL_MIN,  ///< 915 MHz IEEE 802.15.4-2006
    OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MIN  = 11,                                          ///< 2.4 GHz IEEE 802.15.4-2006
    OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MAX  = 26,                                          ///< 2.4 GHz IEEE 802.15.4-2006
    OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MASK = 0xffff << OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MIN, ///< 2.4 GHz IEEE 802.15.4-2006
};

/**
 * This type represents radio capabilities.
 *
 * The value is a bit-field indicating the capabilities supported by the radio. See `OT_RADIO_CAPS_*` definitions.
 *
 */
typedef uint8_t otRadioCaps;

/**
 * This enumeration defines constants that are used to indicate different radio capabilities. See `otRadioCaps`.
 *
 */
enum
{
    OT_RADIO_CAPS_NONE             = 0,      ///< Radio supports no capability.
    OT_RADIO_CAPS_ACK_TIMEOUT      = 1 << 0, ///< Radio supports AckTime event.
    OT_RADIO_CAPS_ENERGY_SCAN      = 1 << 1, ///< Radio supports Energy Scans.
    OT_RADIO_CAPS_TRANSMIT_RETRIES = 1 << 2, ///< Radio supports tx retry logic with collision avoidance (CSMA).
    OT_RADIO_CAPS_CSMA_BACKOFF     = 1 << 3, ///< Radio supports CSMA backoff for frame transmission (but no retry).
};

#define OT_PANID_BROADCAST 0xffff ///< IEEE 802.15.4 Broadcast PAN ID

/**
 * This type represents the IEEE 802.15.4 PAN ID.
 *
 */
typedef uint16_t otPanId;

/**
 * This type represents the IEEE 802.15.4 Short Address.
 *
 */
typedef uint16_t otShortAddress;

#define OT_EXT_ADDRESS_SIZE 8 ///< Size of an IEEE 802.15.4 Extended Address (bytes)

/**
 * @struct otExtAddress
 *
 * This structure represents the IEEE 802.15.4 Extended Address.
 *
 */
OT_TOOL_PACKED_BEGIN
struct otExtAddress
{
    uint8_t m8[OT_EXT_ADDRESS_SIZE]; ///< IEEE 802.15.4 Extended Address bytes
} OT_TOOL_PACKED_END;

/**
 * This structure represents the IEEE 802.15.4 Extended Address.
 *
 */
typedef struct otExtAddress otExtAddress;

/**
 * This structure represents the IEEE 802.15.4 Header IE (Information Element) related information of a radio frame.
 */
typedef struct otRadioIeInfo
{
    int64_t mNetworkTimeOffset; ///< The time offset to the Thread network time.
    uint8_t mTimeIeOffset;      ///< The Time IE offset from the start of PSDU.
    uint8_t mTimeSyncSeq;       ///< The Time sync sequence.
} otRadioIeInfo;

/**
 * This structure represents an IEEE 802.15.4 radio frame.
 */
typedef struct otRadioFrame
{
    uint8_t *mPsdu; ///< The PSDU.

    uint16_t mLength;  ///< Length of the PSDU.
    uint8_t  mChannel; ///< Channel used to transmit/receive the frame.

    /**
     * The union of transmit and receive information for a radio frame.
     */
    union
    {
        /**
         * Structure representing radio frame transmit information.
         */
        struct
        {
            const uint8_t *mAesKey;            ///< The key used for AES-CCM frame security.
            otRadioIeInfo *mIeInfo;            ///< The pointer to the Header IE(s) related information.
            uint8_t        mMaxCsmaBackoffs;   ///< Maximum number of backoffs attempts before declaring CCA failure.
            uint8_t        mMaxFrameRetries;   ///< Maximum number of retries allowed after a transmission failure.
            bool           mIsARetx : 1;       ///< True if this frame is a retransmission (ignored by radio driver).
            bool           mCsmaCaEnabled : 1; ///< Set to true to enable CSMA-CA for this packet, false otherwise.
        } mTxInfo;

        /**
         * Structure representing radio frame receive information.
         */
        struct
        {
            /**
             * The timestamp when the frame was received in microseconds.
             *
             * The value SHALL be the time when the SFD was received when TIME_SYNC or CSL is enabled.
             * Otherwise, the time when the MAC frame was fully received is also acceptable.
             *
             */
            uint64_t mTimestamp;

            int8_t  mRssi; ///< Received signal strength indicator in dBm for received frames.
            uint8_t mLqi;  ///< Link Quality Indicator for received frames.

            // Flags
            bool mAckedWithFramePending : 1; /// This indicates if this frame was acknowledged with frame pending set.
        } mRxInfo;
    } mInfo;
} otRadioFrame;

/**
 * This structure represents the state of a radio.
 * Initially, a radio is in the Disabled state.
 */
typedef enum otRadioState
{
    OT_RADIO_STATE_DISABLED = 0,
    OT_RADIO_STATE_SLEEP    = 1,
    OT_RADIO_STATE_RECEIVE  = 2,
    OT_RADIO_STATE_TRANSMIT = 3,
    OT_RADIO_STATE_INVALID  = 255,
} otRadioState;

/**
 * This structure represents radio coexistence metrics.
 */
typedef struct otRadioCoexMetrics
{
    uint32_t mNumGrantGlitch;          ///< Number of grant glitches.
    uint32_t mNumTxRequest;            ///< Number of tx requests.
    uint32_t mNumTxGrantImmediate;     ///< Number of tx requests while grant was active.
    uint32_t mNumTxGrantWait;          ///< Number of tx requests while grant was inactive.
    uint32_t mNumTxGrantWaitActivated; ///< Number of tx requests while grant was inactive that were ultimately granted.
    uint32_t mNumTxGrantWaitTimeout;   ///< Number of tx requests while grant was inactive that timed out.
    uint32_t mNumTxGrantDeactivatedDuringRequest; ///< Number of tx that were in progress when grant was deactivated.
    uint32_t mNumTxDelayedGrant;                  ///< Number of tx requests that were not granted within 50us.
    uint32_t mAvgTxRequestToGrantTime;            ///< Average time in usec from tx request to grant.
    uint32_t mNumRxRequest;                       ///< Number of rx requests.
    uint32_t mNumRxGrantImmediate;                ///< Number of rx requests while grant was active.
    uint32_t mNumRxGrantWait;                     ///< Number of rx requests while grant was inactive.
    uint32_t mNumRxGrantWaitActivated; ///< Number of rx requests while grant was inactive that were ultimately granted.
    uint32_t mNumRxGrantWaitTimeout;   ///< Number of rx requests while grant was inactive that timed out.
    uint32_t mNumRxGrantDeactivatedDuringRequest; ///< Number of rx that were in progress when grant was deactivated.
    uint32_t mNumRxDelayedGrant;                  ///< Number of rx requests that were not granted within 50us.
    uint32_t mAvgRxRequestToGrantTime;            ///< Average time in usec from rx request to grant.
    uint32_t mNumRxGrantNone;                     ///< Number of rx requests that completed without receiving grant.
    bool     mStopped;                            ///< Stats collection stopped due to saturation.
} otRadioCoexMetrics;

/**
 * @}
 *
 */

/**
 * Get the radio's CCA ED threshold in dBm.
 *
 * @param[in] aInstance    The OpenThread instance structure.
 * @param[out] aThreshold  The CCA ED threshold in dBm.
 *
 * @retval OT_ERROR_NONE             Successfully retrieved the CCA ED threshold.
 * @retval OT_ERROR_INVALID_ARGS     @p aThreshold was NULL.
 * @retval OT_ERROR_NOT_IMPLEMENTED  CCA ED threshold configuration via dBm is not implemented.
 *
 */
otError otPlatRadioGetCcaEnergyDetectThreshold(otInstance *aInstance, int8_t *aThreshold);

/**
 * Set the radio's CCA ED threshold in dBm.
 *
 * @param[in] aInstance   The OpenThread instance structure.
 * @param[in] aThreshold  The CCA ED threshold in dBm.
 *
 * @retval OT_ERROR_NONE             Successfully set the transmit power.
 * @retval OT_ERROR_INVALID_ARGS     Given threshold is out of range.
 * @retval OT_ERROR_NOT_IMPLEMENTED  CCA ED threshold configuration via dBm is not implemented.
 *
 */
otError otPlatRadioSetCcaEnergyDetectThreshold(otInstance *aInstance, int8_t aThreshold);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // end of extern "C"
#endif

#endif // OPENTHREAD_PLATFORM_RADIO_H_
