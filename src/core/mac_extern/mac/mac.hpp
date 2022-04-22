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
 *   This file includes definitions for the IEEE 802.15.4 MAC.
 */

#ifndef MAC_EXTERN_HPP_
#define MAC_EXTERN_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_USE_EXTERNAL_MAC

#include <openthread/platform/radio-mac.h>
#include <openthread/platform/time.h>

#include "common/locator.hpp"
#include "common/log.hpp"
#include "common/non_copyable.hpp"
#include "common/notifier.hpp"
#include "common/tasklet.hpp"
#include "common/time.hpp"
#include "common/timer.hpp"
#include "mac/channel_mask.hpp"
#include "mac/mac_filter.hpp"
#include "mac/mac_frame.hpp"
#include "mac/mac_links.hpp"
#include "mac/mac_types.hpp"
#include "mac/sub_mac.hpp"
#include "radio/trel_link.hpp"
#include "thread/key_manager.hpp"
#include "thread/link_quality.hpp"
#include "thread/network_diagnostic_tlvs.hpp"

namespace ot {

class MeshSender;
class Neighbor;
namespace Mle {
class MleRouter;
}

/**
 * @addtogroup core-mac
 *
 * @brief
 *   This module includes definitions for the IEEE 802.15.4 MAC
 *
 * @{
 *
 */

namespace Mac {

constexpr uint16_t kScanDurationDefault = OPENTHREAD_CONFIG_MAC_SCAN_DURATION; ///< Duration per channel (in msec).

constexpr uint8_t kMaxCSMABackoffs = 4; ///< macMaxCSMABackoffs (IEEE 802.15.4-2006).
constexpr uint8_t kMaxFrameRetries = 3; ///< macMaxFrameRetries (IEEE 802.15.4-2006).

constexpr uint8_t kMaxCsmaBackoffsCsl = 0;
constexpr uint8_t kMaxFrameRetriesCsl = 0;

constexpr uint8_t kBeaconOrderInvalid = 15; ///< Invalid value for beacon order which causes it to be ignored.

/**
 * This type defines the function pointer called on receiving an IEEE 802.15.4 Beacon during an Active Scan.
 *
 */
typedef otHandleActiveScanResult ActiveScanHandler;

/**
 * This type defines an Active Scan result.
 *
 */
typedef otActiveScanResult ActiveScanResult;

/**
 * This type defines the function pointer which is called during an Energy Scan when the scan result for a channel is
 * ready or when the scan completes.
 *
 */
typedef otHandleEnergyScanResult EnergyScanHandler;

/**
 * This type defines an Energy Scan result.
 *
 */
typedef otEnergyScanResult EnergyScanResult;

/**
 * This class implements the IEEE 802.15.4 MAC.
 *
 */
class Mac : public InstanceLocator, private NonCopyable
{
    friend class ot::Instance;

public:
    /**
     * This constructor initializes the MAC object.
     *
     * @param[in]  aInstance  A reference to the OpenThread instance.
     *
     */
    explicit Mac(Instance &aInstance);

    /**
     * This method starts an IEEE 802.15.4 Active Scan.
     *
     * @param[in]  aScanChannels  A bit vector indicating which channels to scan.
     * @param[in]  aScanDuration  The time in milliseconds to spend scanning each channel.
     * @param[in]  aHandler       A pointer to a function that is called on receiving an IEEE 802.15.4 Beacon.
     * @param[in]  aContext       A pointer to an arbitrary context (used when invoking `aHandler` callback).
     *
     * @retval kErrorNone  Successfully scheduled the Active Scan request.
     * @retval kErrorBusy  Could not schedule the scan (a scan is ongoing or scheduled).
     *
     */
    Error ActiveScan(uint32_t aScanChannels, uint16_t aScanDuration, ActiveScanHandler aHandler, void *aContext);

    /**
     * This method starts an IEEE 802.15.4 Energy Scan.
     *
     * @param[in]  aScanChannels     A bit vector indicating on which channels to scan.
     * @param[in]  aScanDuration     The time in milliseconds to spend scanning each channel.
     * @param[in]  aHandler          A pointer to a function called to pass on scan result or indicate scan completion.
     * @param[in]  aContext          A pointer to an arbitrary context (used when invoking @p aHandler callback).
     *
     * @retval kErrorNone  Accepted the Energy Scan request.
     * @retval kErrorBusy  Could not start the energy scan.
     *
     */
    Error EnergyScan(uint32_t aScanChannels, uint16_t aScanDuration, EnergyScanHandler aHandler, void *aContext);

    /**
     * This method indicates the energy scan for the current channel is complete.
     *
     * @param[in]  aEnergyScanMaxRssi  The maximum RSSI encountered on the scanned channel.
     *
     */
    void EnergyScanDone(int8_t aEnergyScanMaxRssi);

    /**
     * This method handles an MLME scan confirm
     *
     * @param[in]  aScanConfirm     A pointer to the otScanConfirm parameter struct
     *
     */
    void HandleScanConfirm(otScanConfirm *aScanConfirm);

    /**
     * This method handles an MLME beacon notification
     *
     * @param[in]  aBeaconNotify     A pointer to the otBeaconNotify parameter struct
     *
     */
    void HandleBeaconNotification(otBeaconNotify *aBeaconNotify);

    /**
     * This method indicates whether or not IEEE 802.15.4 Beacon transmissions are enabled.
     *
     * @retval TRUE   If IEEE 802.15.4 Beacon transmissions are enabled.
     * @retval FALSE  If IEEE 802.15.4 Beacon transmissions are not enabled.
     *
     */
    bool IsBeaconEnabled(void) const { return mBeaconsEnabled; }

    /**
     * This method enables/disables IEEE 802.15.4 Beacon transmissions.
     *
     * @param[in]  aEnabled  TRUE to enable IEEE 802.15.4 Beacon transmissions, FALSE otherwise.
     *
     */
    void SetBeaconEnabled(bool aEnabled);

    /**
     * This method indicates whether or not rx-on-when-idle is enabled.
     *
     * @retval TRUE   If rx-on-when-idle is enabled.
     * @retval FALSE  If rx-on-when-idle is not enabled.
     */
    bool GetRxOnWhenIdle(void) const { return mRxOnWhenIdle; }

    /**
     * This method sets the rx-on-when-idle mode.
     *
     * @param[in]  aRxOnWhenIdle  The rx-on-when-idle mode.
     *
     */
    void SetRxOnWhenIdle(bool aRxOnWhenIdle);

    /**
     * Request the hardmac to send a poll
     *
     * @param[in]  aPollReq  SAP for a poll request
     *
     * @retval kErrorNone     Successfully sent a poll
     * @retval kErrorNoAck   Poll wasn't acked by the destination
     *
     */
    Error SendDataPoll(otPollRequest &aPollReq);

    /**
     * This method requests a direct data frame transmission.
     *
     */
    void RequestDirectFrameTransmission(void);

    /**
     * This method requests an indirect data frame transmission.
     *
     */
    void RequestIndirectFrameTransmission(void);

#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    /**
     * This method requests `Mac` to start a CSL tx operation after a delay of @p aDelay time.
     *
     * @param[in]  aDelay  Delay time for `Mac` to start a CSL tx, in units of milliseconds.
     *
     */
    void RequestCslFrameTransmission(uint32_t aDelay);
#endif

    /**
     * This method purges an indirect frame from the MAC.
     *
     * @param aMsduHandle The MSDU handle of the frame being purged.
     *
     * @retval kErrorNone Frame successfully purged from MAC
     * @retval kErrorNotFound Frame not found in MAC
     */
    Error PurgeIndirectFrame(uint8_t aMsduHandle);

    /**
     * This method registers an Out of Band frame for MAC Transmission.
     * An Out of Band frame is one that was generated outside of OpenThread.
     *
     * @param[in]  aOobFrame  A pointer to the frame.
     *
     * @retval kErrorNotImplemented     Not implemented
     *
     */
    Error SendOutOfBandFrameRequest(otRadioFrame *aOobFrame)
    {
        (void)aOobFrame;
        return kErrorNotImplemented;
    }

    /**
     * This method generates a random IEEE 802.15.4 Extended Address.
     *
     * @param[out]  aExtAddress  A pointer to where the generated Extended Address is placed.
     *
     */
    void GenerateExtAddress(ExtAddress *aExtAddress);

    /**
     * This method returns a reference to the IEEE 802.15.4 Extended Address.
     *
     * @returns A pointer to the IEEE 802.15.4 Extended Address.
     *
     */
    const ExtAddress &GetExtAddress(void) const { return mExtAddress; }

    /**
     * This method sets the IEEE 802.15.4 Extended Address.
     *
     * @param[in]  aExtAddress  A reference to the IEEE 802.15.4 Extended Address.
     *
     */
    void SetExtAddress(const ExtAddress &aExtAddress);

    /**
     * This method returns the IEEE 802.15.4 Short Address.
     *
     * @returns The IEEE 802.15.4 Short Address.
     *
     */
    ShortAddress GetShortAddress(void) const { return mShortAddress; }

    /**
     * This method sets the IEEE 802.15.4 Short Address.
     *
     * @param[in]  aShortAddress  The IEEE 802.15.4 Short Address.
     *
     * @retval kErrorNone  Successfully set the IEEE 802.15.4 Short Address.
     *
     */
    Error SetShortAddress(ShortAddress aShortAddress);

    /**
     * This method returns the IEEE 802.15.4 Channel.
     *
     * @returns The IEEE 802.15.4 Channel.
     *
     */
    uint8_t GetPanChannel(void) const { return mChannel; }

    /**
     * This method sets the IEEE 802.15.4 Channel.
     *
     * @param[in]  aChannel  The IEEE 802.15.4 Channel.
     *
     * @retval kErrorNone          Successfully set the IEEE 802.15.4 Channel.
     *
     */
    Error SetPanChannel(uint8_t aChannel);

    /**
     * This method sets the temporary IEEE 802.15.4 radio channel.
     *
     * This method allows user to temporarily change the radio channel and use a different channel (during receive)
     * instead of the PAN channel (from `SetPanChannel()`). A call to `ClearTemporaryChannel()` would clear the
     * temporary channel and adopt the PAN channel again. The `SetTemporaryChannel()` can be used multiple times in row
     * (before a call to `ClearTemporaryChannel()`) to change the temporary channel.
     *
     * @param[in]  aChannel            A IEEE 802.15.4 channel.
     *
     * @retval kErrorNone          Successfully set the temporary channel
     * @retval kErrorInvalidArgs   The @p aChannel is not in the supported channel mask.
     *
     */
    Error SetTemporaryChannel(uint8_t aChannel);

    /**
     * This method clears the use of a previously set temporary channel and adopts the PAN channel.
     *
     */
    Error ClearTemporaryChannel(void);

    /**
     * This method returns the supported channel mask.
     *
     * @returns The supported channel mask.
     *
     */
    const ChannelMask &GetSupportedChannelMask(void) const { return mSupportedChannelMask; }

    /**
     * This method sets the supported channel mask
     *
     * @param[in] aMask   The supported channel mask.
     *
     */
    void SetSupportedChannelMask(const ChannelMask &aMask);

    /**
     * This method returns the IEEE 802.15.4 Network Name.
     *
     * @returns A reference to the IEEE 802.15.4 Network Name.
     *
     */
    const NetworkName &GetNetworkName(void) const { return mNetworkName; }

    /**
     * This method sets the IEEE 802.15.4 Network Name.
     *
     * @param[in]  aNetworkName   A pointer to the IEEE 802.15.4 Network Name.
     *
     * @retval kErrorNone          Successfully set the IEEE 802.15.4 Network Name.
     *
     */
    Error SetNetworkName(const char *aNetworkName);

    /**
     * This method sets the IEEE 802.15.4 Network Name.
     *
     * @param[in]  aNameData     A name data (length and char buffer).
     *
     * @retval kErrorNone          Successfully set the IEEE 802.15.4 Network Name.
     * @retval kErrorInvalidArgs   Given name is too long.
     *
     */
    Error SetNetworkName(const NameData &aNameData);

#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
    /**
     * This method returns the Thread Domain Name.
     *
     * @returns The Thread Domain Name.
     *
     */
    const DomainName &GetDomainName(void) const { return mDomainName; }

    /**
     * This method sets the Thread Domain Name.
     *
     * @param[in]  aNameString   A pointer to a string character array. Must be null terminated.
     *
     * @retval kErrorNone          Successfully set the Thread Domain Name.
     * @retval kErrorInvalidArgs   Given name is too long.
     *
     */
    Error SetDomainName(const char *aNameString);

    /**
     * This method sets the Thread Domain Name.
     *
     * @param[in]  aNameData     A name data (pointer to char buffer and length).
     *
     * @retval kErrorNone          Successfully set the Thread Domain Name.
     * @retval kErrorInvalidArgs   Given name is too long.
     *
     */
    Error SetDomainName(const NameData &aNameData);
#endif // (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)

    /**
     * This method returns the IEEE 802.15.4 PAN ID.
     *
     * @returns The IEEE 802.15.4 PAN ID.
     *
     */
    uint16_t GetPanId(void) const { return mPanId; }

    /**
     * This method sets the IEEE 802.15.4 PAN ID.
     *
     * @param[in]  aPanId  The IEEE 802.15.4 PAN ID.
     *
     * @retval kErrorNone  Successfully set the IEEE 802.15.4 PAN ID.
     *
     */
    Error SetPanId(PanId aPanId);

    /**
     * This method returns the IEEE 802.15.4 Extended PAN ID.
     *
     * @returns A pointer to the IEEE 802.15.4 Extended PAN ID.
     *
     */
    const ExtendedPanId &GetExtendedPanId(void) const { return mExtendedPanId; }

    /**
     * This method sets the IEEE 802.15.4 Extended PAN ID.
     *
     * @param[in]  aExtendedPanId  The IEEE 802.15.4 Extended PAN ID.
     *
     * @retval kErrorNone  Successfully set the IEEE 802.15.4 Extended PAN ID.
     *
     */
    Error SetExtendedPanId(const ExtendedPanId &aExtendedPanId);

    /**
     * This method returns the maximum number of frame retries during direct transmission.
     *
     * @returns The maximum number of retries during direct transmission.
     *
     */
    uint8_t GetMaxFrameRetriesDirect(void);

    /**
     * This method sets the maximum number of frame retries during direct transmission.
     *
     * @param[in]  aMaxFrameRetriesDirect  The maximum number of retries during direct transmission.
     *
     */
    void SetMaxFrameRetriesDirect(uint8_t aMaxFrameRetriesDirect);

#if OPENTHREAD_FTD
    /**
     * This method returns the maximum number of frame retries during indirect transmission.
     *
     * @returns The maximum number of retries during indirect transmission.
     *
     */
    uint8_t GetMaxFrameRetriesIndirect(void) const { return 255; }

    /**
     * This method sets the maximum number of frame retries during indirect transmission.
     *
     * @param[in]  aMaxFrameRetriesIndirect  The maximum number of retries during indirect transmission.
     *
     */
    void SetMaxFrameRetriesIndirect(uint8_t aMaxFrameRetriesIndirect) { OT_UNUSED_VARIABLE(aMaxFrameRetriesIndirect); }
#endif

#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
    /**
     * This method returns the MAC filter.
     *
     * @returns A reference to the MAC filter.
     *
     */
    Filter &GetFilter(void) { return mFilter; }
#endif // OPENTHREAD_CONFIG_MAC_FILTER_ENABLE

    /**
     * This method is called to handle received data packets
     *
     * @param[in]  aFrame  A pointer to the otDataIndication primitive
     *
     */
    void ProcessDataIndication(otDataIndication *aDataIndication);

    /**
     * This method is called to handle received data packets that failed security
     *
     * @param[in]  aFrame  A pointer to the otCommStatusIndication primitive
     *
     */
    void ProcessCommStatusIndication(otCommStatusIndication *aCommStatusIndication);

    /**
     * This method is called to handle received poll command packets that did
     * not trigger a data response.
     *
     * @param[in]  aFrame  A pointer to the otPollIndication primitive
     *
     */
    void ProcessPollIndication(otPollIndication *aPollIndication);

    /**
     * This method is called to handle transmission start events.
     *
     * @param[in]  aFrame  A pointer to the frame that is transmitted.
     */
    void TransmitStartedTask(otRadioFrame *aFrame);

    /**
     * This method is called to handle transmit events.
     *
     * @param[in]  aFrame      A pointer to the frame that was transmitted.
     * @param[in]  aAckFrame   A pointer to the ACK frame, NULL if no ACK was received.
     * @param[in]  aError      OT_ERROR_NONE when the frame was transmitted, OT_ERROR_NO_ACK when the frame was
     *                         transmitted but no ACK was received, OT_ERROR_CHANNEL_ACCESS_FAILURE when the
     *                         transmission could not take place due to activity on the channel, OT_ERROR_ABORT when
     *                         transmission was aborted for other reasons.
     *
     */
    void TransmitDoneTask(uint8_t aMsduHandle, otError aError);

    /**
     * This method returns if a scan is in progress.
     *
     */
    bool IsScanInProgress(void);

    /**
     * This method returns if an active scan is in progress.
     *
     */
    bool IsActiveScanInProgress(void);

    /**
     * This method returns if an energy scan is in progress.
     *
     */
    bool IsEnergyScanInProgress(void);

    /**
     * This method returns if the MAC layer is in transmit state.
     *
     * The MAC layer is in transmit state during CSMA/CA, CCA, transmission of Data, Beacon or Data Request frames and
     * receiving of ACK frames. The MAC layer is not in transmit state during transmission of ACK frames or Beacon
     * Requests.
     *
     */
    bool IsInTransmitState(void);

    /**
     * This method registers a callback to provide received raw IEEE 802.15.4 frames.
     *
     * @param[in]  aPcapCallback     A pointer to a function that is called when receiving an IEEE 802.15.4 link frame
     *                               or `nullptr` to disable the callback.
     * @param[in]  aCallbackContext  A pointer to application-specific context.
     *
     */
    void SetPcapCallback(otLinkPcapCallback aPcapCallback, void *aCallbackContext);

    /**
     * This method indicates whether or not promiscuous mode is enabled at the link layer.
     *
     * @retval true   Promiscuous mode is enabled.
     * @retval false  Promiscuous mode is not enabled.
     *
     */
    bool IsPromiscuous(void);

    /**
     * This method enables or disables the link layer promiscuous mode.
     *
     * Promiscuous mode keeps the receiver enabled, overriding the value of mRxOnWhenIdle.
     *
     * @param[in]  aPromiscuous  true to enable promiscuous mode, or false otherwise.
     *
     */
    void SetPromiscuous(bool aPromiscuous);

    /**
     * This method fills network diagnostic MacCounterTlv.
     *
     * @param[in]  aMacCountersTlv The reference to the network diagnostic MacCounterTlv.
     *
     */
    void FillMacCountersTlv(NetworkDiagnostic::MacCountersTlv &aMacCounters) const;

    /**
     * This method resets mac counters
     *
     */
    void ResetCounters(void);

    /**
     * This method returns the MAC counter.
     *
     * @returns A reference to the MAC counter.
     *
     */
    otMacCounters &GetCounters(void) { return mCounters; }

    /**
     * This method returns the noise floor value (currently use the radio receive sensitivity value).
     *
     * @returns The noise floor value in dBm.
     *
     */
    int8_t GetNoiseFloor(void);

    /**
     * This method configures the external MAC for thread
     *
     * @retval kErrorNone  Success.
     *
     */
    Error Start(void);

    /**
     * This method resets the external MAC so that it stops
     *
     * @retval kErrorNone  Success.
     *
     */
    Error Stop(void);

    /**
     * This method queries the external mac device table and caches the frame counter for
     * the provided neighbor in its data
     *
     * @param[in]  aNeighbor  The neighbor to cache the frame counter for
     *
     */
    void CacheDevice(Neighbor &aNeighbor);

    /**
     * This method sets the frame counter for a neighbor device in the PIB to
     * match the value stored locally.
     *
     * @param[in]  aNeighbor  The neighbor to update the frame counter for
     *
     */
    Error UpdateDevice(Neighbor &aNeighbor);

    /**
     * This method queries the external mac device table and caches the frame counters in the
     * relevant neighbour data structure.
     *
     */
    void CacheDeviceTable(void);

    /**
     * This method rebuilds the key and device tables for the external mac
     *
     */
    void BuildSecurityTable(void);

    /**
     * This method returns the current frame counter for this device
     *
     * @returns The current frame counter
     *
     */
    uint32_t GetFrameCounter(void);

    /**
     * This method sets the current frame counter in the PIB
     *
     * @param[in]  aFrameCounter  The value of the frame counter to set
     *
     */
    void SetFrameCounter(uint32_t aFrameCounter);

    /**
     * This method Starts/Stops the Link layer. It may only be used when the Netif Interface is down.
     *
     * @param[in]  aEnable The requested State for the MAC layer. true - Start, false - Stop.
     *
     * @retval kErrorNone The operation succeeded or the new State equals the current State.
     */
    Error SetEnabled(bool aEnable);

    /**
     * This method returns the current CCA (Clear Channel Assessment) failure rate.
     *
     * The rate is maintained over a window of (roughly) last `OPENTHREAD_CONFIG_CCA_FAILURE_RATE_AVERAGING_WINDOW`
     * frame transmissions.
     *
     * @returns The CCA failure rate with maximum value `0xffff` corresponding to 100% failure rate.
     *
     */
    uint16_t GetCcaFailureRate(void) const { return mCcaSuccessRateTracker.GetFailureRate(); }

    /**
     * This method indicates whether or not the link layer is enabled.
     *
     * @retval true   Link layer is enabled.
     * @retval false  Link layer is not enabled.
     *
     */
    bool IsEnabled(void) { return mEnabled; }

    /**
     * This method gets a valid MsduHandle for using to identify frames sent via the MAC.
     *
     * @returns  A valid 8-bit identifier handle to use in an TxFrame
     */
    uint8_t GetValidMsduHandle(void);

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
    /**
     * This method gets the CSL channel.
     *
     * @returns CSL channel.
     *
     */
    uint8_t GetCslChannel(void) const { return mLinks.GetSubMac().GetCslChannel(); }

    /**
     * This method sets the CSL channel.
     *
     * @param[in]  aChannel  The CSL channel.
     *
     */
    void SetCslChannel(uint8_t aChannel);

    /**
     * This method indicates if CSL channel has been explicitly specified by the upper layer.
     *
     * @returns If CSL channel has been specified.
     *
     */
    bool IsCslChannelSpecified(void) const { return mLinks.GetSubMac().IsCslChannelSpecified(); }

    /**
     * This method gets the CSL period.
     *
     * @returns CSL period in units of 10 symbols.
     *
     */
    uint16_t GetCslPeriod(void) const { return mLinks.GetSubMac().GetCslPeriod(); }

    /**
     * This method sets the CSL period.
     *
     * @param[in]  aPeriod  The CSL period in 10 symbols.
     *
     */
    void SetCslPeriod(uint16_t aPeriod);

    /**
     * This method indicates whether CSL is started at the moment.
     *
     * @retval TRUE   If CSL is enabled.
     * @retval FALSE  If CSL is not enabled.
     *
     */
    bool IsCslEnabled(void) const;

    /**
     * This method indicates whether Link is capable of starting CSL.
     *
     * @retval TRUE   If Link is capable of starting CSL.
     * @retval FALSE  If link is not capable of starting CSL.
     *
     */
    bool IsCslCapable(void) const;

    /**
     * This method returns CSL parent clock accuracy, in ± ppm.
     *
     * @retval CSL parent clock accuracy, in ± ppm.
     *
     */
    uint8_t GetCslParentClockAccuracy(void) const { return mLinks.GetSubMac().GetCslParentClockAccuracy(); }

    /**
     * This method sets CSL parent clock accuracy, in ± ppm.
     *
     * @param[in] aCslParentAccuracy CSL parent clock accuracy, in ± ppm.
     *
     */
    void SetCslParentClockAccuracy(uint8_t aCslParentAccuracy)
    {
        mLinks.GetSubMac().SetCslParentClockAccuracy(aCslParentAccuracy);
    }

    /**
     * This method returns CSL parent uncertainty, in ±10 us units.
     *
     * @retval CSL parent uncertainty, in ±10 us units.
     *
     */
    uint8_t GetCslParentUncertainty(void) const { return mLinks.GetSubMac().GetCslParentUncertainty(); }

    /**
     * This method returns CSL parent uncertainty, in ±10 us units.
     *
     * @param[in] aCslParentUncert  CSL parent uncertainty, in ±10 us units.
     *
     */
    void SetCslParentUncertainty(uint8_t aCslParentUncert)
    {
        mLinks.GetSubMac().SetCslParentUncertainty(aCslParentUncert);
    }
#endif // OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE

#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE && OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    /**
     * This method enables/disables the 802.15.4 radio filter.
     *
     * When radio filter is enabled, radio is put to sleep instead of receive (to ensure device does not receive any
     * frame and/or potentially send ack). Also the frame transmission requests return immediately without sending the
     * frame over the air (return "no ack" error if ack is requested, otherwise return success).
     *
     * @param[in] aFilterEnabled    TRUE to enable radio filter, FALSE to disable.
     *
     */
    void SetRadioFilterEnabled(bool aFilterEnabled);

    /**
     * This method indicates whether the 802.15.4 radio filter is enabled or not.
     *
     * @retval TRUE   If the radio filter is enabled.
     * @retval FALSE  If the radio filter is disabled.
     *
     */
    bool IsRadioFilterEnabled(void) const { return mLinks.GetSubMac().IsRadioFilterEnabled(); }
#endif

private:
    static constexpr int8_t   kInvalidRssiValue  = 127;
    static constexpr uint16_t kMaxCcaSampleCount = OPENTHREAD_CONFIG_CCA_FAILURE_RATE_AVERAGING_WINDOW;

    enum Operation : uint8_t
    {
        kOperationIdle = 0,
        kOperationActiveScan,
        kOperationEnergyScan,
        kOperationTransmitDataDirect,
        kOperationTransmitDataIndirect,
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
        kOperationTransmitDataCsl,
#endif
    };

    void  ProcessTransmitSecurity(otSecSpec &aSecSpec);
    Error ProcessReceiveSecurity(otSecSpec &aSecSpec, Neighbor *aNeighbor);
#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2
    Error ProcessEnhAckSecurity(TxFrame &aTxFrame, RxFrame &aAckFrame);
#endif

    bool IsPending(Operation aOperation) const { return mPendingOperations & (1U << aOperation); }
    bool IsActiveOrPending(Operation aOperation) const;
    void SetPending(Operation aOperation) { mPendingOperations |= (1U << aOperation); }
    void ClearPending(Operation aOperation) { mPendingOperations &= ~(1U << aOperation); }
    void StartOperation(Operation aOperation);
    void FinishOperation(void);
    void BuildBeacon(void);
    void HandleBeginDirect(void);
#if OPENTHREAD_FTD
    void HandleBeginIndirect(void);
#endif
    Error ProcessTransmitStatus(Error aTransmitError);
    void  Scan(Operation aScanOperation, uint32_t aScanChannels, uint16_t aScanDuration);
    void  HandleBeginScan(void);

    void  ReportActiveScanResult(const otBeaconNotify *aBeacon);
    Error SignalNetworkNameChange(Error aError);

    otError BuildDeviceDescriptor(const ExtAddress &aExtAddress,
                                  uint32_t          aFrameCounter,
                                  PanId             aPanId,
                                  uint16_t          shortAddr,
                                  uint8_t           aIndex);
    otError BuildDeviceDescriptor(Neighbor &aNeighbor, uint8_t &aIndex);
    otError BuildRouterDeviceDescriptors(uint8_t &aDevIndex, uint8_t aIgnoreRouterId);
    void    BuildJoinerKeyDescriptor(uint8_t aIndex);
    void    BuildMainKeyDescriptors(uint8_t &aIndex);
    void    BuildMode2KeyDescriptor(uint8_t aIndex);
    void    HotswapJoinerRouterKeyDescriptor(uint8_t *aDstAddr);
    void    BuildKeyTable(void);

    uint8_t GetCurrentChannel(void);
    otError SetTempTxChannel(TxFrame &aTxFrame);
    otError ClearTempTxChannel();

    otError RadioReceive(uint8_t aChannel);

    static void sStateChangedCallback(Notifier::Callback &aCallback, uint32_t aFlags);
    void        stateChangedCallback(uint32_t aFlags);

    static const char *OperationToString(Operation aOperation);

    static void CopyReversedExtAddr(const ExtAddress &aExtAddrIn, uint8_t *aExtAddrOut);
    static void CopyReversedExtAddr(const uint8_t *aExtAddrIn, ExtAddress &aExtAddrOut);

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    void ProcessCsl(const RxFrame &aFrame, const Address &aSrcAddr);
#endif
#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_SUBJECT_ENABLE
    void ProcessEnhAckProbing(const RxFrame &aFrame, const Neighbor &aNeighbor);
#endif

    bool mRxOnWhenIdle : 1;
    bool mBeaconsEnabled : 1;
    bool mUseTempTxChannel : 1;
    bool mUseTempRxChannel : 1;
    bool mJoinerEntrustResponseRequested : 1;
    bool mDirectAckRequested : 1;
    bool mEnabled : 1;
#if OPENTHREAD_CONFIG_STAY_AWAKE_BETWEEN_FRAGMENTS
    bool mDelaySleep : 1;
#endif

    Operation    mOperation;
    Address      mDirectDstAddress;
    ExtAddress   mExtAddress;
    ShortAddress mShortAddress;
    uint16_t     mPendingOperations;
    PanId        mPanId;
    uint8_t      mChannel;
    uint8_t      mTempRxChannel;
    uint8_t      mTempTxChannel;
    uint8_t      mNextMsduHandle;
    uint8_t      mDirectMsduHandle;
    uint8_t      mDynamicKeyIndex;
    uint8_t      mMode2DevHandle;
    uint8_t      mActiveNeighborCount;
    ChannelMask  mSupportedChannelMask;

    uint8_t mDeviceCurrentKeys[OPENTHREAD_CONFIG_EXTERNAL_MAC_DEVICE_TABLE_SIZE];

    Notifier::Callback mNotifierCallback;

    ExtendedPanId mExtendedPanId;
    NetworkName   mNetworkName;
#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
    DomainName mDomainName;
#endif
    uint32_t mScanChannels;
    uint16_t mScanDuration;
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    TimeMilli mCslTxFireTime;
#endif

    union
    {
        ActiveScanHandler mActiveScanHandler;
        EnergyScanHandler mEnergyScanHandler;
    };

    TxFrame mDirectDataReq;
    union
    {
        TxFrame        mIndirectDataReq;
        otScanRequest  mScanReq;
        otStartRequest mStartReq;
    }

    void *mScanHandlerContext;

    Links              mLinks;
    SuccessRateTracker mCcaSuccessRateTracker;
    uint16_t           mCcaSampleCount;
    otMacCounters      mCounters;

#if OPENTHREAD_CONFIG_MULTI_RADIO
    RadioTypes mTxPendingRadioLinks;
    RadioTypes mTxBeaconRadioLinks;
    Error      mTxError;
#endif

#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
    Filter mFilter;
#endif

    KeyMaterial mMode2KeyMaterial;

    static const otExtAddress    sMode2ExtAddress;
    static const otExtendedPanId sExtendedPanidInit;
    static const char            sNetworkNameInit[];
    static const char            sDomainNameInit[];
};

/**
 * @}
 *
 */

} // namespace Mac
} // namespace ot

#endif // OPENTHREAD_CONFIG_USE_EXTERNAL_MAC
#endif // MAC_EXTERN_HPP_
