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
 *   This file implements the subset of IEEE 802.15.4 primitives required for Thread.
 */

#include "mac/mac.hpp"

#if OPENTHREAD_CONFIG_USE_EXTERNAL_MAC

#include "utils/wrap_string.h"

#include <openthread/random_noncrypto.h>

#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/encoding.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/locator.hpp"
#include "common/logging.hpp"
#include "common/notifier.hpp"
#include "crypto/aes_ccm.hpp"
#include "crypto/sha256.hpp"
#include "mac/mac_frame.hpp"
#include "thread/mle_router.hpp"
#include "thread/thread_netif.hpp"

using ot::Encoding::BigEndian::HostSwap64;

namespace ot {
namespace Mac {

const uint8_t Mac::sMode2Key[] = {0x78, 0x58, 0x16, 0x86, 0xfd, 0xb4, 0x58, 0x0f,
                                  0xb0, 0x92, 0x54, 0x6a, 0xec, 0xbd, 0x15, 0x66};

const otExtAddress Mac::sMode2ExtAddress = {
    {0x35, 0x06, 0xfe, 0xb8, 0x23, 0xd4, 0x87, 0x12},
};

const otExtendedPanId Mac::sExtendedPanidInit = {
    {0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0xca, 0xfe},
};
const char Mac::sNetworkNameInit[] = "OpenThread";

Mac::Mac(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mOperation(kOperationIdle)
    , mShortAddress(kShortAddrInvalid)
    , mPanId(kPanIdBroadcast)
    , mChannel(OPENTHREAD_CONFIG_DEFAULT_CHANNEL)
    , mNextMsduHandle(1)
    , mDynamicKeyIndex(0)
    , mMode2DevHandle(0)
    , mSupportedChannelMask(Radio::kSupportedChannels)
    , mDeviceCurrentKeys()
    , mNotifierCallback(aInstance, sStateChangedCallback, this)
    , mScanChannels(0)
    , mScanDuration(0)
    , mActiveScanHandler(NULL) // Initialize `mActiveScanHandler` and `mEnergyScanHandler` union
#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
    , mFilter()
#endif // OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
{
    GenerateExtAddress(&mExtAddress);
    otPlatRadioEnable(&GetInstance());
    SetExtendedPanId(static_cast<const ExtendedPanId &>(sExtendedPanidInit));
    SetNetworkName(sNetworkNameInit);
    SetPanId(mPanId);
    SetExtAddress(mExtAddress);
    SetShortAddress(mShortAddress);
    mCcaSuccessRateTracker.Reset();
    ResetCounters();
}

otError Mac::ActiveScan(uint32_t aScanChannels, uint16_t aScanDuration, ActiveScanHandler aHandler)
{
    otError error;

    mActiveScanHandler = aHandler;
    SuccessOrExit(error = Scan(kOperationActiveScan, aScanChannels, aScanDuration));
exit:

    if (OT_ERROR_NONE != error)
    {
        mActiveScanHandler = NULL;
    }

    return error;
}

otError Mac::EnergyScan(uint32_t aScanChannels, uint16_t aScanDuration, EnergyScanHandler aHandler)
{
    otError error;

    mEnergyScanHandler = aHandler;
    SuccessOrExit(error = Scan(kOperationEnergyScan, aScanChannels, aScanDuration));
exit:

    if (OT_ERROR_NONE != error)
    {
        mEnergyScanHandler = NULL;
    }

    return error;
}

otError Mac::Scan(Operation aScanOperation, uint32_t aScanChannels, uint16_t aScanDuration)
{
    otError error        = OT_ERROR_NONE;
    uint8_t scanDuration = 0; // The scan duration as defined by the 802.15.4 spec as being
                              // log2(aScanDuration/(aBaseSuperframeDuration * aSymbolPeriod))

    VerifyOrExit(mEnabled, error = OT_ERROR_INVALID_STATE);
    VerifyOrExit(!IsScanInProgress(), error = OT_ERROR_BUSY);

    aScanChannels = (aScanChannels == 0) ? GetSupportedChannelMask().GetMask() : aScanChannels;
    aScanDuration = (aScanDuration == 0) ? static_cast<uint16_t>(kScanDurationDefault) : aScanDuration;

    // 15 ~= (aBaseSuperframeDuration * aSymbolPeriod_us)/1000
    aScanDuration = aScanDuration / 15;

    // scanDuration = log2(aScanDuration)
    while ((aScanDuration = aScanDuration >> 1) != 0)
    {
        scanDuration++;
    }

    mScanChannels = aScanChannels;
    mScanDuration = scanDuration;

    StartOperation(aScanOperation);

exit:
    return error;
}

void Mac::HandleBeginScan()
{
    otScanRequest &scanReq = mScanReq;

    memset(&scanReq, 0, sizeof(scanReq));
    scanReq.mScanChannelMask = mScanChannels;
    scanReq.mScanDuration    = mScanDuration;
    scanReq.mScanType        = (mOperation == kOperationActiveScan) ? OT_MAC_SCAN_TYPE_ACTIVE : OT_MAC_SCAN_TYPE_ENERGY;

    otPlatMlmeScan(&GetInstance(), &scanReq);
}

bool Mac::IsScanInProgress(void)
{
    return (IsActiveScanInProgress() || IsEnergyScanInProgress());
}

bool Mac::IsActiveScanInProgress(void)
{
    return (mOperation == kOperationActiveScan) || (mPendingActiveScan);
}

bool Mac::IsEnergyScanInProgress(void)
{
    return (mOperation == kOperationEnergyScan) || (mPendingEnergyScan);
}

bool Mac::IsInTransmitState(void)
{
    return mDirectMsduHandle;
}

extern "C" void otPlatMlmeScanConfirm(otInstance *aInstance, otScanConfirm *aScanConfirm)
{
    Instance *instance = static_cast<Instance *>(aInstance);

    VerifyOrExit(instance->IsInitialized());
    instance->Get<Mac>().HandleScanConfirm(aScanConfirm);

exit:
    return;
}

void Mac::HandleScanConfirm(otScanConfirm *aScanConfirm)
{
    uint8_t channel = GetCurrentChannel();

    VerifyOrExit(IsScanInProgress());

    if (IsActiveScanInProgress())
    {
        VerifyOrExit(mActiveScanHandler != NULL);
        mActiveScanHandler(GetInstance(), NULL);
    }
    else
    {
        uint8_t curChannel = 10;
        VerifyOrExit(mEnergyScanHandler != NULL);

        // Call the callback once for each result
        for (int i = 0; i < aScanConfirm->mResultListSize; i++)
        {
            otEnergyScanResult result;
            while (!(mScanChannels & (1 << curChannel)))
            {
                curChannel++;
            }
            result.mMaxRssi = aScanConfirm->mResultList[i];
            result.mChannel = curChannel;

            mScanChannels &= ~(1 << curChannel);
            mEnergyScanHandler(GetInstance(), &result);
        }
        mEnergyScanHandler(GetInstance(), NULL);
    }

exit:
    // Restore channel
    otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &channel);
    FinishOperation();

    return;
}

extern "C" void otPlatMlmeBeaconNotifyIndication(otInstance *aInstance, otBeaconNotify *aBeaconNotify)
{
    Instance *instance = static_cast<Instance *>(aInstance);

    VerifyOrExit(instance->IsInitialized());
    instance->Get<Mac>().HandleBeaconNotification(aBeaconNotify);

exit:
    return;
}

void Mac::HandleBeaconNotification(otBeaconNotify *aBeaconNotify)
{
    VerifyOrExit(mActiveScanHandler != NULL);
    VerifyOrExit(aBeaconNotify != NULL);

    mActiveScanHandler(GetInstance(), aBeaconNotify);
exit:
    return;
}

otError Mac::ConvertBeaconToActiveScanResult(otBeaconNotify *aBeaconNotify, otActiveScanResult &aResult)
{
    otError        error         = OT_ERROR_NONE;
    BeaconPayload *beaconPayload = NULL;

    memset(&aResult, 0, sizeof(aResult));

    VerifyOrExit(aBeaconNotify != NULL, error = OT_ERROR_INVALID_ARGS);
    VerifyOrExit(aBeaconNotify->mPanDescriptor.Coord.mAddressMode == OT_MAC_ADDRESS_MODE_EXT, error = OT_ERROR_PARSE);

    memcpy(&aResult.mExtAddress, aBeaconNotify->mPanDescriptor.Coord.mAddress, sizeof(aResult.mExtAddress));
    aResult.mPanId   = Encoding::LittleEndian::ReadUint16(aBeaconNotify->mPanDescriptor.Coord.mPanId);
    aResult.mChannel = aBeaconNotify->mPanDescriptor.LogicalChannel;
    aResult.mRssi    = aBeaconNotify->mPanDescriptor.LinkQuality;
    aResult.mLqi     = aBeaconNotify->mPanDescriptor.LinkQuality;

    beaconPayload = reinterpret_cast<BeaconPayload *>(aBeaconNotify->mSdu);

    if ((aBeaconNotify->mSduLength >= sizeof(*beaconPayload)) && beaconPayload->IsValid())
    {
        aResult.mVersion    = beaconPayload->GetProtocolVersion();
        aResult.mIsJoinable = beaconPayload->IsJoiningPermitted();
        aResult.mIsNative   = beaconPayload->IsNative();
        static_cast<NetworkName &>(aResult.mNetworkName).Set(beaconPayload->GetNetworkName());
        aResult.mExtendedPanId = beaconPayload->GetExtendedPanId();
    }
    else
    {
        error = OT_ERROR_PARSE;
    }

exit:
    return error;
}

void Mac::SetRxOnWhenIdle(bool aRxOnWhenIdle)
{
    uint8_t setVal;
    VerifyOrExit(mRxOnWhenIdle != aRxOnWhenIdle);

    mRxOnWhenIdle = aRxOnWhenIdle;
    setVal        = mRxOnWhenIdle ? 1 : 0;
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_RX_ON_WHEN_IDLE, 0, 1, &setVal);

exit:
    return;
}

otError Mac::SendDataPoll(otPollRequest &aPollReq)
{
    otError error = OT_ERROR_NONE;

    ProcessTransmitSecurity(aPollReq.mSecurity);
    error = otPlatMlmePollRequest(&GetInstance(), &aPollReq);
    error = ProcessTransmitStatus(error);

    return error;
}

void Mac::GenerateExtAddress(ExtAddress *aExtAddress)
{
    otRandomNonCryptoFillBuffer(aExtAddress->m8, sizeof(ExtAddress));
    aExtAddress->SetGroup(false);
    aExtAddress->SetLocal(true);
}

void Mac::SetExtAddress(const ExtAddress &aExtAddress)
{
    otExtAddress address;

    CopyReversedExtAddr(aExtAddress, address.m8);

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_IEEE_ADDRESS, 0, OT_EXT_ADDRESS_SIZE, address.m8);
    mExtAddress = aExtAddress;
}

otError Mac::SetShortAddress(ShortAddress aShortAddress)
{
    otError error = OT_ERROR_NONE;

    uint8_t shortAddr[2];
    mShortAddress = aShortAddress;
    Encoding::LittleEndian::WriteUint16(mShortAddress, shortAddr);
    error = otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_SHORT_ADDRESS, 0, 2, shortAddr);
    return error;
}

otError Mac::SetPanChannel(uint8_t aChannel)
{
    otError error      = OT_ERROR_NONE;
    uint8_t oldChannel = GetCurrentChannel();

    VerifyOrExit(mSupportedChannelMask.ContainsChannel(aChannel), error = OT_ERROR_INVALID_ARGS);
    mChannel = aChannel;

    VerifyOrExit(!mUseTempRxChannel && !mUseTempTxChannel);
    VerifyOrExit(oldChannel != mChannel);

    error = otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &mChannel);
    mCcaSuccessRateTracker.Reset();

exit:
    return error;
}

otError Mac::SetTemporaryChannel(uint8_t aTempChannel)
{
    otError error      = OT_ERROR_NONE;
    uint8_t newChannel = aTempChannel;
    uint8_t oldChannel = GetCurrentChannel();

    mUseTempRxChannel = true;
    mTempRxChannel    = newChannel;

    VerifyOrExit(newChannel != oldChannel);

    VerifyOrExit(mSupportedChannelMask.ContainsChannel(newChannel), error = OT_ERROR_INVALID_ARGS);

    VerifyOrExit(error = otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &newChannel));

exit:
    return error;
}

otError Mac::SetTempTxChannel(TxFrame &aTxFrame)
{
    otError error      = OT_ERROR_NONE;
    uint8_t newChannel = aTxFrame.GetChannel();
    uint8_t oldChannel = GetCurrentChannel();

    mUseTempTxChannel = true;
    mTempTxChannel    = newChannel;

    VerifyOrExit(newChannel != oldChannel);

    VerifyOrExit(mSupportedChannelMask.ContainsChannel(newChannel), error = OT_ERROR_INVALID_ARGS);

    VerifyOrExit(error = otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &newChannel));

exit:
    return error;
}

uint8_t Mac::GetCurrentChannel()
{
    if (mUseTempTxChannel)
        return mTempTxChannel;
    if (mUseTempRxChannel)
        return mTempRxChannel;
    return mChannel;
}

otError Mac::ClearTemporaryChannel()
{
    otError error      = OT_ERROR_NONE;
    uint8_t curChannel = GetCurrentChannel();
    uint8_t newChannel;

    mUseTempRxChannel = false;
    newChannel        = GetCurrentChannel();

    if (newChannel != curChannel)
        VerifyOrExit(error = otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &newChannel));

exit:
    return error;
}

otError Mac::ClearTempTxChannel()
{
    otError error      = OT_ERROR_NONE;
    uint8_t curChannel = GetCurrentChannel();
    uint8_t newChannel;

    mUseTempTxChannel = false;
    newChannel        = GetCurrentChannel();

    if (newChannel != curChannel)
        VerifyOrExit(error = otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &newChannel));

exit:
    return error;
}

void Mac::SetSupportedChannelMask(const ChannelMask &aMask)
{
    ChannelMask newMask = aMask;

    newMask.Intersect(ChannelMask(Radio::kSupportedChannels));
    VerifyOrExit(newMask != mSupportedChannelMask, Get<Notifier>().SignalIfFirst(OT_CHANGED_SUPPORTED_CHANNEL_MASK));

    mSupportedChannelMask = newMask;
    Get<Notifier>().Signal(OT_CHANGED_SUPPORTED_CHANNEL_MASK);

exit:
    return;
}

otError Mac::SetNetworkName(const char *aNetworkName)
{
    NetworkName::Data data(aNetworkName, NetworkName::kMaxSize + 1);

    return SetNetworkName(data);
}

otError Mac::SetNetworkName(const NetworkName::Data &aName)
{
    otError error = mNetworkName.Set(aName);

    if (error == OT_ERROR_ALREADY)
    {
        error = OT_ERROR_NONE;
        Get<Notifier>().SignalIfFirst(OT_CHANGED_THREAD_NETWORK_NAME);
        BuildBeacon();
    }
    else if (error == OT_ERROR_NONE)
    {
        Get<Notifier>().Signal(OT_CHANGED_THREAD_NETWORK_NAME);
        BuildBeacon();
    }

    return error;
}

otError Mac::SetPanId(PanId aPanId)
{
    uint8_t panId[2];
    otError error = OT_ERROR_NONE;

    VerifyOrExit(mPanId != aPanId);
    mPanId = aPanId;
    Encoding::LittleEndian::WriteUint16(mPanId, panId);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_PAN_ID, 0, 2, panId);
    BuildSecurityTable();

exit:
    return error;
}

otError Mac::SetExtendedPanId(const ExtendedPanId &aExtendedPanId)
{
    Get<Notifier>().Update(mExtendedPanId, aExtendedPanId, OT_CHANGED_THREAD_EXT_PANID);
    BuildBeacon();
    return OT_ERROR_NONE;
}

uint8_t Mac::GetMaxFrameRetriesDirect()
{
    uint8_t macMaxRetries = 3;
    uint8_t len           = 1;
    otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_MAX_FRAME_RETRIES, 0, &len, &macMaxRetries);
    return macMaxRetries;
}

void Mac::SetMaxFrameRetriesDirect(uint8_t aMaxFrameRetriesDirect)
{
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_MAX_FRAME_RETRIES, 0, 1, &aMaxFrameRetriesDirect);
}

otError Mac::RequestDirectFrameTransmission(void)
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(mEnabled, error = OT_ERROR_INVALID_STATE);
    VerifyOrExit(!mPendingTransmitDataDirect && !mDirectMsduHandle, error = OT_ERROR_ALREADY);

    StartOperation(kOperationTransmitDataDirect);

exit:
    return error;
}

otError Mac::RequestIndirectFrameTransmission(void)
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(mEnabled, error = OT_ERROR_INVALID_STATE);
    VerifyOrExit(!mPendingTransmitDataIndirect, error = OT_ERROR_ALREADY);

    StartOperation(kOperationTransmitDataIndirect);

exit:
    return error;
}

otError Mac::PurgeIndirectFrame(uint8_t aMsduHandle)
{
    otError error = otPlatMcpsPurge(&GetInstance(), aMsduHandle);
    otLogDebgMac("Purged handle %x with error %s", aMsduHandle, otThreadErrorToString(error));
    return error;
}

void Mac::StartOperation(Operation aOperation)
{
    if (aOperation != kOperationIdle)
    {
        otLogDebgMac("Request to start operation \"%s\"", OperationToString(aOperation));
    }

    if (!mEnabled)
    {
        mPendingActiveScan           = false;
        mPendingEnergyScan           = false;
        mPendingTransmitDataDirect   = false;
        mPendingTransmitDataIndirect = false;
        ExitNow();
    }

    switch (aOperation)
    {
    case kOperationIdle:
        break;

    case kOperationActiveScan:
        mPendingActiveScan = true;
        break;

    case kOperationEnergyScan:
        mPendingEnergyScan = true;
        break;

    case kOperationTransmitDataDirect:
        mPendingTransmitDataDirect = true;
        break;

    case kOperationTransmitDataIndirect:
        mPendingTransmitDataIndirect = true;
        break;
    }

    VerifyOrExit(mOperation == kOperationIdle);

    if (mPendingActiveScan)
    {
        mPendingActiveScan = false;
        mOperation         = kOperationActiveScan;
        HandleBeginScan();
    }
    else if (mPendingEnergyScan)
    {
        mPendingEnergyScan = false;
        mOperation         = kOperationEnergyScan;
        HandleBeginScan();
    }
    else if (mPendingTransmitDataDirect)
    {
        mPendingTransmitDataDirect = false;
        mOperation                 = kOperationTransmitDataDirect;
        HandleBeginDirect();
    }
#if OPENTHREAD_FTD
    else if (mPendingTransmitDataIndirect)
    {
        mPendingTransmitDataIndirect = false;
        mOperation                   = kOperationTransmitDataIndirect;
        HandleBeginIndirect();
    }
#endif

    if (mOperation != kOperationIdle)
    {
        otLogDebgMac("Starting operation \"%s\"", OperationToString(mOperation));
    }

    if (mOperation == kOperationTransmitDataDirect || mOperation == kOperationTransmitDataIndirect)
    {
        FinishOperation();
    }

exit:
    return;
}

void Mac::FinishOperation(void)
{
    // Clear the current operation and start any pending ones.
    otLogDebgMac("Finishing operation \"%s\"", OperationToString(mOperation));

    mOperation = kOperationIdle;
    StartOperation(kOperationIdle);
}

void Mac::SetBeaconEnabled(bool aEnabled)
{
    VerifyOrExit(mBeaconsEnabled != aEnabled);
    mBeaconsEnabled = aEnabled;

    if (mBeaconsEnabled)
    {
        otStartRequest &startReq = mStartReq;

        memset(&startReq, 0, sizeof(startReq));

        startReq.mPanId           = mPanId;
        startReq.mLogicalChannel  = mChannel;
        startReq.mBeaconOrder     = kBeaconOrderInvalid;
        startReq.mSuperframeOrder = kBeaconOrderInvalid;
        startReq.mPanCoordinator  = 1;
        otPlatMlmeStart(&GetInstance(), &startReq);

        BuildBeacon();
    }
    else
    {
        otPlatMlmeReset(&GetInstance(), false);
    }

exit:
    return;
}

void Mac::BuildBeacon()
{
    uint8_t       numUnsecurePorts;
    uint8_t       beaconLength  = 0;
    BeaconPayload beaconPayload = BeaconPayload();

    if (Get<KeyManager>().GetSecurityPolicyFlags() & OT_SECURITY_POLICY_BEACONS)
    {
        beaconPayload.Init();

        // set the Joining Permitted flag
        Get<Ip6::Filter>().GetUnsecurePorts(numUnsecurePorts);

        if (numUnsecurePorts)
        {
            beaconPayload.SetJoiningPermitted();
        }
        else
        {
            beaconPayload.ClearJoiningPermitted();
        }

        beaconPayload.SetNetworkName(mNetworkName.GetAsData());
        beaconPayload.SetExtendedPanId(mExtendedPanId);

        beaconLength = sizeof(beaconPayload);
    }

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_BEACON_PAYLOAD, 0, beaconLength,
                  reinterpret_cast<uint8_t *>(&beaconPayload));
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_BEACON_PAYLOAD_LENGTH, 0, 1, &beaconLength);
}

void Mac::CopyReversedExtAddr(const ExtAddress &aExtAddrIn, uint8_t *aExtAddrOut)
{
    size_t len = sizeof(aExtAddrIn);
    for (uint8_t i = 0; i < len; i++)
    {
        aExtAddrOut[i] = aExtAddrIn.m8[len - i - 1];
    }
}

void Mac::CopyReversedExtAddr(const uint8_t *aExtAddrIn, ExtAddress &aExtAddrOut)
{
    size_t len = sizeof(aExtAddrOut);
    for (uint8_t i = 0; i < len; i++)
    {
        aExtAddrOut.m8[i] = aExtAddrIn[len - i - 1];
    }
}

// TODO: Clean up entire security table section to be better abstracted
otError Mac::BuildDeviceDescriptor(const ExtAddress &aExtAddress,
                                   uint32_t          aFrameCounter,
                                   PanId             aPanId,
                                   uint16_t          shortAddr,
                                   uint8_t           aIndex)
{
    otPibDeviceDescriptor deviceDescriptor;

    memset(&deviceDescriptor, 0, sizeof(deviceDescriptor));

    CopyReversedExtAddr(aExtAddress, deviceDescriptor.mExtAddress);
    Encoding::LittleEndian::WriteUint32(aFrameCounter, deviceDescriptor.mFrameCounter);
    Encoding::LittleEndian::WriteUint16(aPanId, deviceDescriptor.mPanId);
    Encoding::LittleEndian::WriteUint16(shortAddr, deviceDescriptor.mShortAddress);

    otLogDebgMac("Built device descriptor at index %d", aIndex);
    otLogDebgMac("Short Address: 0x%04x", shortAddr);
    otLogDebgMac("Ext Address: %02x%02x%02x%02x%02x%02x%02x%02x", deviceDescriptor.mExtAddress[0],
                 deviceDescriptor.mExtAddress[1], deviceDescriptor.mExtAddress[2], deviceDescriptor.mExtAddress[3],
                 deviceDescriptor.mExtAddress[4], deviceDescriptor.mExtAddress[5], deviceDescriptor.mExtAddress[6],
                 deviceDescriptor.mExtAddress[7]);
    otLogDebgMac("Frame Counter: 0x%08x", aFrameCounter);

    return otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, aIndex, sizeof(deviceDescriptor),
                         reinterpret_cast<uint8_t *>(&deviceDescriptor));
}

otError Mac::BuildDeviceDescriptor(Neighbor &aNeighbor, uint8_t &aIndex)
{
    otError error     = OT_ERROR_NONE;
    int32_t keyOffset = 0, keyNum = 0;
    uint8_t reps = 1;

    keyNum = 1 + Get<KeyManager>().GetCurrentKeySequence() - aNeighbor.GetKeySequence();
    VerifyOrExit(keyNum >= 0 && keyNum <= 2, error = OT_ERROR_SECURITY);

#if !OPENTHREAD_CONFIG_EXTERNAL_MAC_SHARED_DD
    reps      = 3;
    keyOffset = keyNum;
#endif

    mDeviceCurrentKeys[aIndex / reps] = keyNum;

    aNeighbor.SetDeviceTableIndex(aIndex + static_cast<uint8_t>(keyOffset));

    for (int i = 0; i < reps; i++)
    {
        uint32_t fc = aNeighbor.GetLinkFrameCounter();

        if (i < keyOffset) // No way to track old FCs or modify them in higher layer so receiving to old key is
                           // inherently unsafe
        {
            fc = 0xFFFFFFFF;
        }
        error = BuildDeviceDescriptor(aNeighbor.GetExtAddress(), fc, mPanId, aNeighbor.GetRloc16(), aIndex);
        VerifyOrExit(error == OT_ERROR_NONE);
        aIndex += 1;
    }

exit:
    return error;
}

otError Mac::BuildRouterDeviceDescriptors(uint8_t &aDevIndex, uint8_t &aNumActiveDevices, uint8_t aIgnoreRouterId)
{
    otError error = OT_ERROR_NONE;

    for (ChildTable::Iterator iter(GetInstance(), Child::kInStateValidOrRestoring); !iter.IsDone(); iter++)
    {
        BuildDeviceDescriptor(*iter.GetChild(), aDevIndex);
        aNumActiveDevices++;
    }

    for (RouterTable::Iterator iter(GetInstance()); !iter.IsDone(); iter++)
    {
        Router *router = iter.GetRouter();

        if (router->GetRouterId() == aIgnoreRouterId)
            continue; // Ignore self

        if (Get<Mle::MleRouter>().GetNeighbor(router->GetRloc16()) == NULL)
            continue; // Ignore non-neighbors

        error = BuildDeviceDescriptor(*router, aDevIndex);
        VerifyOrExit(error == OT_ERROR_NONE);
        aNumActiveDevices++;
    }

exit:
    return error;
}

void Mac::CacheDevice(Neighbor &aNeighbor)
{
    uint8_t               len;
    uint8_t               index = aNeighbor.GetDeviceTableIndex();
    otPibDeviceDescriptor deviceDesc;
    ExtAddress            addr;
    otError               error = OT_ERROR_NONE;

    error =
        otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, index, &len, reinterpret_cast<uint8_t *>(&deviceDesc));
    VerifyOrExit(error == OT_ERROR_NONE);
    assert(len == sizeof(deviceDesc));

    CopyReversedExtAddr(deviceDesc.mExtAddress, addr);
    VerifyOrExit(memcmp(&addr, &(aNeighbor.GetExtAddress()), sizeof(addr)) == 0);

    aNeighbor.SetLinkFrameCounter(Encoding::LittleEndian::ReadUint32(deviceDesc.mFrameCounter));

exit:
    if (error != OT_ERROR_NONE)
    {
        // Fall back to caching entire device table
        CacheDeviceTable();
    }
}

otError Mac::UpdateDevice(Neighbor &aNeighbor)
{
    uint8_t               len;
    uint8_t               index = aNeighbor.GetDeviceTableIndex();
    otPibDeviceDescriptor deviceDesc;
    ExtAddress            addr;
    otError               error = OT_ERROR_NONE;

    VerifyOrExit(aNeighbor.IsStateValidOrRestoring(), error = OT_ERROR_NOT_FOUND);

    error =
        otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, index, &len, reinterpret_cast<uint8_t *>(&deviceDesc));
    VerifyOrExit(error == OT_ERROR_NONE);
    assert(len == sizeof(deviceDesc));

    CopyReversedExtAddr(deviceDesc.mExtAddress, addr);
    VerifyOrExit(memcmp(&addr, &(aNeighbor.GetExtAddress()), sizeof(addr)) == 0, error = OT_ERROR_NOT_FOUND);

    Encoding::LittleEndian::WriteUint32(aNeighbor.GetLinkFrameCounter(), deviceDesc.mFrameCounter);
    error =
        otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, index, len, reinterpret_cast<uint8_t *>(&deviceDesc));

exit:
    return error;
}

void Mac::CacheDeviceTable()
{
    uint8_t len;
    uint8_t numDevices;

    otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE_ENTRIES, 0, &len, &numDevices);
    assert(len == 1);

    for (uint8_t i = 0; i < numDevices; i++)
    {
        otPibDeviceDescriptor deviceDesc;
        Neighbor *            neighbor;
        Address               addr;

        otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, i, &len, reinterpret_cast<uint8_t *>(&deviceDesc));
        assert(len == sizeof(deviceDesc));

        addr.SetShort(Encoding::LittleEndian::ReadUint16(deviceDesc.mShortAddress));

        if (addr.GetShort() == kShortAddrInvalid)
        {
            addr.SetExtended(deviceDesc.mExtAddress, ExtAddress::kReverseByteOrder);
        }

        neighbor = Get<Mle::MleRouter>().GetNeighbor(addr);

        if (neighbor != NULL)
        {
            neighbor->SetLinkFrameCounter(Encoding::LittleEndian::ReadUint32(deviceDesc.mFrameCounter));
        }
    }
}

void Mac::BuildJoinerKeyDescriptor(uint8_t aIndex)
{
#if OPENTHREAD_CONFIG_JOINER_ENABLE
    otKeyTableEntry keyTableEntry;
    ExtAddress      counterpart;

    memset(&keyTableEntry, 0, sizeof(keyTableEntry));
    memcpy(keyTableEntry.mKey, Get<KeyManager>().GetKek(), sizeof(keyTableEntry.mKey));
    keyTableEntry.mKeyIdLookupListEntries = 1;
    keyTableEntry.mKeyUsageListEntries    = 1;
    keyTableEntry.mKeyDeviceListEntries   = 1;

    keyTableEntry.mKeyIdLookupDesc[0].mLookupDataSizeCode = OT_MAC_LOOKUP_DATA_SIZE_CODE_9_OCTETS;
    Get<MeshCoP::Joiner>().GetCounterpartAddress(counterpart);
    CopyReversedExtAddr(counterpart, &(keyTableEntry.mKeyIdLookupDesc[0].mLookupData[1]));

    keyTableEntry.mKeyDeviceDesc[0].mDeviceDescriptorHandle = 0;

    keyTableEntry.mKeyUsageDesc[0].mFrameType = Frame::kFcfFrameData;

    otLogDebgMac("Built joiner key descriptor at index %d", aIndex);
    otLogDebgMac("Lookup Data: %02x%02x%02x%02x%02x%02x%02x%02x%02x", keyTableEntry.mKeyIdLookupDesc[0].mLookupData[0],
                 keyTableEntry.mKeyIdLookupDesc[0].mLookupData[1], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[2],
                 keyTableEntry.mKeyIdLookupDesc[0].mLookupData[3], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[4],
                 keyTableEntry.mKeyIdLookupDesc[0].mLookupData[5], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[6],
                 keyTableEntry.mKeyIdLookupDesc[0].mLookupData[7], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[8]);

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_KEY_TABLE, aIndex, sizeof(keyTableEntry),
                  reinterpret_cast<uint8_t *>(&keyTableEntry));
#else
    (void)aIndex;
#endif
}

void Mac::BuildMainKeyDescriptors(uint8_t aDeviceCount, uint8_t &aIndex)
{
    otKeyTableEntry keyTableEntry;
    uint32_t        keySequence = Get<KeyManager>().GetCurrentKeySequence() - 1;
    uint8_t         ddReps      = 3;

#if OPENTHREAD_CONFIG_EXTERNAL_MAC_SHARED_DD
    ddReps = 1;
#endif

    VerifyOrExit(aDeviceCount > 0);
    memset(&keyTableEntry, 0, sizeof(keyTableEntry));

    keyTableEntry.mKeyIdLookupListEntries = 1;
    keyTableEntry.mKeyUsageListEntries    = 2;
    keyTableEntry.mKeyDeviceListEntries   = aDeviceCount;

    keyTableEntry.mKeyIdLookupDesc[0].mLookupDataSizeCode = OT_MAC_LOOKUP_DATA_SIZE_CODE_9_OCTETS;
    keyTableEntry.mKeyIdLookupDesc[0].mLookupData[8]      = 0xFF; // keyIndex || macDefaultKeySource

    keyTableEntry.mKeyUsageDesc[0].mFrameType      = Frame::kFcfFrameData;
    keyTableEntry.mKeyUsageDesc[1].mFrameType      = Frame::kFcfFrameMacCmd;
    keyTableEntry.mKeyUsageDesc[1].mCommandFrameId = Frame::kMacCmdDataRequest;

    for (int i = 0; i < 3; i++)
    {
        const uint8_t *key = Get<KeyManager>().GetTemporaryMacKey(keySequence);
        memcpy(keyTableEntry.mKey, key, sizeof(keyTableEntry.mKey));
        keyTableEntry.mKeyIdLookupDesc[0].mLookupData[0] = (keySequence & 0x7F) + 1;

        for (int j = 0; j < aDeviceCount; j++)
        {
            keyTableEntry.mKeyDeviceDesc[j].mDeviceDescriptorHandle = (j * ddReps) + (i % ddReps);

            if (i < mDeviceCurrentKeys[j])
                keyTableEntry.mKeyDeviceDesc[j].mBlacklisted = 1;
            else
                keyTableEntry.mKeyDeviceDesc[j].mBlacklisted = 0;

#if OPENTHREAD_CONFIG_EXTERNAL_MAC_SHARED_DD
            if (i > mDeviceCurrentKeys[j])
                keyTableEntry.mKeyDeviceDesc[j].mNew = 1;
            else
                keyTableEntry.mKeyDeviceDesc[j].mNew = 0;
#endif
        }

        otLogDebgMac("Built Key at index %d", aIndex);
        for (int j = 0; j < aDeviceCount; j++)
        {
            otLogDebgMac("Device Desc handle %d, blacklisted %d",
                         keyTableEntry.mKeyDeviceDesc[j].mDeviceDescriptorHandle,
                         keyTableEntry.mKeyDeviceDesc[j].mBlacklisted);
        }

        otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_KEY_TABLE, aIndex, sizeof(keyTableEntry),
                      reinterpret_cast<uint8_t *>(&keyTableEntry));

        aIndex++;
        keySequence++;
    }

exit:
    return;
}

void Mac::BuildMode2KeyDescriptor(uint8_t aIndex, uint8_t aMode2DevHandle)
{
    otKeyTableEntry keyTableEntry;

    memset(&keyTableEntry, 0, sizeof(keyTableEntry));

    mDynamicKeyIndex = aIndex;
    mMode2DevHandle  = aMode2DevHandle;

    keyTableEntry.mKeyIdLookupListEntries = 1;
    keyTableEntry.mKeyUsageListEntries    = 1;
    keyTableEntry.mKeyDeviceListEntries   = 1;

    keyTableEntry.mKeyIdLookupDesc[0].mLookupDataSizeCode = OT_MAC_LOOKUP_DATA_SIZE_CODE_5_OCTETS;
    memset(keyTableEntry.mKeyIdLookupDesc[0].mLookupData, 0xFF, 5);

    keyTableEntry.mKeyUsageDesc[0].mFrameType     = Frame::kFcfFrameData;
    keyTableEntry.mKeyDeviceDesc[0].mUniqueDevice = true; // Assumed errata in thread spec says this should be false
    keyTableEntry.mKeyDeviceDesc[0].mDeviceDescriptorHandle = aMode2DevHandle;

    memcpy(keyTableEntry.mKey, sMode2Key, sizeof(keyTableEntry.mKey));

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_KEY_TABLE, aIndex, sizeof(keyTableEntry),
                  reinterpret_cast<uint8_t *>(&keyTableEntry));
}

void Mac::HotswapJoinerRouterKeyDescriptor(uint8_t *aDstAddr)
{
    otKeyTableEntry keyTableEntry;

    memset(&keyTableEntry, 0, sizeof(keyTableEntry));

    keyTableEntry.mKeyIdLookupListEntries = 1;
    keyTableEntry.mKeyUsageListEntries    = 1;
    keyTableEntry.mKeyDeviceListEntries   = 0;

    keyTableEntry.mKeyIdLookupDesc[0].mLookupDataSizeCode = OT_MAC_LOOKUP_DATA_SIZE_CODE_9_OCTETS;
    memcpy(keyTableEntry.mKeyIdLookupDesc[0].mLookupData + 1, aDstAddr, OT_EXT_ADDRESS_SIZE);

    keyTableEntry.mKeyUsageDesc[0].mFrameType = Frame::kFcfFrameData;

    const uint8_t *key = Get<KeyManager>().GetKek();
    memcpy(keyTableEntry.mKey, key, sizeof(keyTableEntry.mKey));

    otLogDebgMac("Built joiner router key descriptor at index %d", mDynamicKeyIndex);
    otLogDebgMac("Lookup Data: %02x%02x%02x%02x%02x%02x%02x%02x%02x", keyTableEntry.mKeyIdLookupDesc[0].mLookupData[0],
                 keyTableEntry.mKeyIdLookupDesc[0].mLookupData[1], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[2],
                 keyTableEntry.mKeyIdLookupDesc[0].mLookupData[3], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[4],
                 keyTableEntry.mKeyIdLookupDesc[0].mLookupData[5], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[6],
                 keyTableEntry.mKeyIdLookupDesc[0].mLookupData[7], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[8]);

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_KEY_TABLE, mDynamicKeyIndex, sizeof(keyTableEntry),
                  reinterpret_cast<uint8_t *>(&keyTableEntry));

    mJoinerEntrustResponseRequested = true;
}

void Mac::BuildSecurityTable()
{
    otDeviceRole role                = Get<Mle::Mle>().GetRole();
    uint8_t      devIndex            = 0;
    uint8_t      keyIndex            = 0;
    uint8_t      numActiveDevices    = 0;
    uint8_t      nextHopForNeighbors = Mle::kInvalidRouterId;
    bool         isJoining           = false;
    bool         isFFD               = (Get<Mle::Mle>().GetDeviceMode().IsFullThreadDevice());

#if OPENTHREAD_CONFIG_JOINER_ENABLE
    isJoining = (Get<MeshCoP::Joiner>().GetState() == OT_JOINER_STATE_CONNECT);
#endif

    // Cache the frame counters so that they remain correct after flushing device table
    CacheDeviceTable();

    // Note: The reason the router table is not specific to the router role is because
    // FFD children have one-way comms (rx-only) with neighboring routers so they must
    // maintain the device table for them. See TS:1.1.1 sec 4.7.7.4

    if ((role == OT_DEVICE_ROLE_CHILD) || role == OT_DEVICE_ROLE_DETACHED)
    {
        Router &parent = Get<Mle::Mle>().GetParentCandidate().IsStateValidOrRestoring()
                             ? Get<Mle::Mle>().GetParentCandidate()
                             : Get<Mle::Mle>().GetParent();

        if (parent.IsStateValidOrRestoring())
        {
            BuildDeviceDescriptor(parent, devIndex);
            numActiveDevices++;
            nextHopForNeighbors = Get<Mle::Mle>().GetRouterId(parent.GetRloc16());
        }
    }
    if (isFFD)
    {
        BuildRouterDeviceDescriptors(devIndex, numActiveDevices, nextHopForNeighbors);
    }
#if OPENTHREAD_CONFIG_JOINER_ENABLE
    if (role == OT_DEVICE_ROLE_DISABLED && isJoining)
    {
        ExtAddress counterpart;
        Get<MeshCoP::Joiner>().GetCounterpartAddress(counterpart);
        Mac::BuildDeviceDescriptor(counterpart, 0, mPanId, 0xFFFF, devIndex++);
    }
#endif

    // Set the mode 2 'device'
    mMode2DevHandle = devIndex++;
    BuildDeviceDescriptor(static_cast<const ExtAddress &>(sMode2ExtAddress), 0, 0xFFFF, 0xFFFF, mMode2DevHandle);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE_ENTRIES, 0, 1, &devIndex);

    // Keys:
    if (isJoining)
    {
#if OPENTHREAD_CONFIG_JOINER_ENABLE
        BuildJoinerKeyDescriptor(keyIndex++);
#endif
    }
    else
    {
        BuildMainKeyDescriptors(numActiveDevices, keyIndex);
    }
    BuildMode2KeyDescriptor(keyIndex++, mMode2DevHandle);

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_KEY_TABLE_ENTRIES, 0, 1, &keyIndex);
    // Finalisation

    otLogInfoMac("Built Security Table with %d devices", numActiveDevices);
}

void Mac::ProcessTransmitSecurity(otSecSpec &aSecSpec)
{
    KeyManager &keyManager = Get<KeyManager>();

    VerifyOrExit(aSecSpec.mSecurityLevel > 0);

    switch (aSecSpec.mKeyIdMode)
    {
    case 0:
        break;

    case 1:
        keyManager.IncrementMacFrameCounter();
        aSecSpec.mKeyIndex = (keyManager.GetCurrentKeySequence() & 0x7f) + 1;
        break;

    case 2:
    {
        const uint8_t keySource[] = {0xff, 0xff, 0xff, 0xff};
        memcpy(aSecSpec.mKeySource, keySource, sizeof(keySource));
        aSecSpec.mKeyIndex = 0xff;
        break;
    }

    default:
        assert(false);
        break;
    }

exit:
    return;
}

void Mac::HandleBeginDirect(void)
{
    TxFrame &sendFrame = mDirectDataReq;
    otError  error     = OT_ERROR_NONE;

    otLogDebgMac("Mac::HandleBeginDirect");
    memset(&sendFrame, 0, sizeof(sendFrame));

    sendFrame.SetChannel(mChannel);
    SuccessOrExit(error = Get<MeshForwarder>().HandleFrameRequest(sendFrame));

    if (sendFrame.mDst.mAddressMode == OT_MAC_ADDRESS_MODE_SHORT &&
        Encoding::LittleEndian::ReadUint16(sendFrame.mDst.mAddress) == kShortAddrBroadcast)
    {
        mCounters.mTxBroadcast++;
    }
    else
    {
        mCounters.mTxUnicast++;
    }

    // Security Processing
    ProcessTransmitSecurity(sendFrame.mSecurity);

    // Assign MSDU handle
    mDirectMsduHandle     = GetValidMsduHandle();
    sendFrame.mMsduHandle = mDirectMsduHandle;

    if (sendFrame.mSecurity.mSecurityLevel > 0 && sendFrame.mSecurity.mKeyIdMode == 0)
    {
        bool isJoining = false;

#if OPENTHREAD_CONFIG_JOINER_ENABLE
        isJoining = (Get<MeshCoP::Joiner>().GetState() != OT_JOINER_STATE_IDLE &&
                     Get<MeshCoP::Joiner>().GetState() != OT_JOINER_STATE_JOINED);
#endif

        if (!isJoining)
        {
            // Hotswap the kek descriptor into keytable for joiner entrust response
            assert(sendFrame.mDst.mAddressMode == OT_MAC_ADDRESS_MODE_EXT);
            HotswapJoinerRouterKeyDescriptor(sendFrame.mDst.mAddress);
        }
    }

    error = SetTempTxChannel(sendFrame);
    assert(error == OT_ERROR_NONE);
    otLogDebgMac("calling otPlatRadioTransmit for direct");
    otLogDebgMac("Sam %x; Dam %x; MH %x;", sendFrame.mSrcAddrMode, sendFrame.mDst.mAddressMode, sendFrame.mMsduHandle);
    otDumpDebgMac("Msdu", sendFrame.mMsdu, sendFrame.mMsduLength);
    mDirectAckRequested = sendFrame.GetAckRequest();
    sendFrame.GetDstAddr(mDirectDstAddress);
    error = otPlatMcpsDataRequest(&GetInstance(), &sendFrame);
    assert(error == OT_ERROR_NONE);

exit:
    return;
}

#if OPENTHREAD_FTD
void Mac::HandleBeginIndirect(void)
{
    TxFrame &sendFrame = mIndirectDataReq;
    otError  error     = OT_ERROR_NONE;

    otLogDebgMac("Mac::HandleBeginIndirect");
    memset(&sendFrame, 0, sizeof(sendFrame));

    sendFrame.SetChannel(mChannel);
    SuccessOrExit(error = Get<DataPollHandler>().HandleFrameRequest(sendFrame));

    mCounters.mTxUnicast++;

    ProcessTransmitSecurity(sendFrame.mSecurity);
    sendFrame.mTxOptions |= OT_MAC_TX_OPTION_INDIRECT;
    sendFrame.mTxOptions |= OT_MAC_TX_OPTION_NS_SECURE_IND;

    otLogDebgMac("calling otPlatRadioTransmit for indirect");
    otLogDebgMac("Sam %x; Dam %x; MH %x;", sendFrame.mSrcAddrMode, sendFrame.mDst.mAddressMode, sendFrame.mMsduHandle);
    otDumpDebgMac("Msdu", sendFrame.mMsdu, sendFrame.mMsduLength);
    error = otPlatMcpsDataRequest(&GetInstance(), &sendFrame);

    assert(error == OT_ERROR_NONE);
exit:
    otLogDebgMac("HandleBeginIndirect: %s", otThreadErrorToString(error));
    return;
}
#endif

void Mac::sStateChangedCallback(Notifier::Callback &aCallback, uint32_t aFlags)
{
    aCallback.GetOwner<Mac>().stateChangedCallback(aFlags);
}

void Mac::stateChangedCallback(uint32_t aFlags)
{
    uint32_t keyUpdateFlags = (OT_CHANGED_THREAD_KEY_SEQUENCE_COUNTER | OT_CHANGED_THREAD_CHILD_ADDED |
                               OT_CHANGED_THREAD_CHILD_REMOVED | OT_CHANGED_THREAD_ROLE);

    if (aFlags & keyUpdateFlags)
    {
        BuildSecurityTable();
    }
}

extern "C" void otPlatMcpsDataConfirm(otInstance *aInstance, uint8_t aMsduHandle, otError aError)
{
    Instance *instance = static_cast<Instance *>(aInstance);
    VerifyOrExit(instance->IsInitialized());

    instance->Get<Mac>().TransmitDoneTask(aMsduHandle, aError);

exit:
    return;
}

otError Mac::ProcessTransmitStatus(otError aTransmitError)
{
    otError error      = aTransmitError;
    bool    ccaSuccess = true;

    switch (error)
    {
    case OT_ERROR_CHANNEL_ACCESS_FAILURE:
        ccaSuccess = false;
        mCounters.mTxErrBusyChannel++;
    // fall through
    case OT_ERROR_NO_ACK:
    case OT_ERROR_NONE:
        if (GetCurrentChannel() == mChannel)
        {
            if (mCcaSampleCount < kMaxCcaSampleCount)
            {
                mCcaSampleCount++;
            }
            mCcaSuccessRateTracker.AddSample(ccaSuccess, mCcaSampleCount);
        }
        break;

    default:
        mCounters.mTxErrAbort++;
        otLogInfoMac("Converting error %s to ABORT", otThreadErrorToString(error));
        error = OT_ERROR_ABORT;
        break;
    }

    return error;
}

void Mac::TransmitDoneTask(uint8_t aMsduHandle, otError aError)
{
    otError error = ProcessTransmitStatus(aError);

    otLogDebgMac("TransmitDoneTask Called");

    if (error != OT_ERROR_NONE)
    {
        otLogDebgMac("Transmit Error: %s", otThreadErrorToString(aError));
    }

    if (aMsduHandle == mDirectMsduHandle)
    {
        if (aError == OT_ERROR_CHANNEL_ACCESS_FAILURE || aError == OT_ERROR_FAILED)
        {
            // Failed without even hitting the air, retry silently.
            error = otPlatMcpsDataRequest(&GetInstance(), &mDirectDataReq);
            assert(error == OT_ERROR_NONE);
            return;
        }
        if (mJoinerEntrustResponseRequested)
        {
            // Restore the mode 2 key after sending the joiner entrust response
            mJoinerEntrustResponseRequested = false;
            BuildMode2KeyDescriptor(mDynamicKeyIndex, mMode2DevHandle);
        }
        if (mUseTempTxChannel)
        {
            ClearTempTxChannel();
        }

        mDirectMsduHandle = 0;
        Get<MeshForwarder>().HandleSentFrame(mDirectAckRequested, error, mDirectDstAddress);
    }
#if OPENTHREAD_FTD
    else
    {
        Get<DataPollHandler>().HandleSentFrame(aError, aMsduHandle);
    }
#endif

    return;
}
otError Mac::ProcessReceiveSecurity(otSecSpec &aSecSpec, Neighbor *aNeighbor)
{
    otError     error = OT_ERROR_NONE;
    uint8_t     keyIdMode;
    uint8_t     keyid;
    uint32_t    keySequence = 0;
    KeyManager &keyManager  = Get<KeyManager>();

    VerifyOrExit(aSecSpec.mSecurityLevel > 0);

    keyIdMode = aSecSpec.mKeyIdMode;

    switch (keyIdMode)
    {
    case 0:
        break;

    case 1:
        VerifyOrExit(aNeighbor != NULL, error = OT_ERROR_SECURITY);

        keyid = aSecSpec.mKeyIndex;
        keyid--;

        if (keyid == (keyManager.GetCurrentKeySequence() & 0x7f))
        {
            // same key index
            keySequence = keyManager.GetCurrentKeySequence();
        }
        else if (keyid == ((keyManager.GetCurrentKeySequence() - 1) & 0x7f))
        {
            // previous key index
            keySequence = keyManager.GetCurrentKeySequence() - 1;
        }
        else if (keyid == ((keyManager.GetCurrentKeySequence() + 1) & 0x7f))
        {
            // next key index
            keySequence = keyManager.GetCurrentKeySequence() + 1;
        }
        else
        {
            otLogCritMac("Incorrect KeySequence passed through HardMac");
            ExitNow(error = OT_ERROR_SECURITY);
        }
        break;

    case 2:
        // Reset the mode 2 device frame counter to 0
        BuildDeviceDescriptor(static_cast<const ExtAddress &>(sMode2ExtAddress), 0, 0xFFFF, 0xFFFF, mMode2DevHandle);
        break;
    }

    if ((keyIdMode == 1) && (aNeighbor->GetState() == Neighbor::kStateValid))
    {
        if (aNeighbor->GetKeySequence() != keySequence)
        {
            aNeighbor->SetKeySequence(keySequence);
            aNeighbor->SetMleFrameCounter(0);
        }

        if (keySequence > keyManager.GetCurrentKeySequence())
        {
            keyManager.SetCurrentKeySequence(keySequence);
        }
    }

exit:
    return error;
}

extern "C" void otPlatMcpsDataIndication(otInstance *aInstance, otDataIndication *aDataIndication)
{
    Instance *instance = static_cast<Instance *>(aInstance);

    VerifyOrExit(instance->IsInitialized());

    instance->Get<Mac>().ProcessDataIndication(aDataIndication);

exit:
    return;
}

void Mac::ProcessDataIndication(otDataIndication *aDataIndication)
{
    RxFrame & dataInd = static_cast<RxFrame &>(*aDataIndication);
    Address   srcaddr, dstaddr;
    Neighbor *neighbor;
    otError   error = OT_ERROR_NONE;
#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
    int8_t rssi = OT_MAC_FILTER_FIXED_RSS_DISABLED;
#endif // OPENTHREAD_CONFIG_MAC_FILTER_ENABLE

    assert(aDataIndication != NULL);

    dataInd.SetChannel(GetCurrentChannel());
    dataInd.GetSrcAddr(srcaddr);
    dataInd.GetDstAddr(dstaddr);
    neighbor = Get<Mle::MleRouter>().GetNeighbor(srcaddr);

    if (dstaddr.IsBroadcast())
        mCounters.mRxBroadcast++;
    else
        mCounters.mRxUnicast++;

    // Allow  multicasts from neighbor routers if FFD
    if (neighbor == NULL && dstaddr.IsBroadcast() && (Get<Mle::Mle>().GetDeviceMode().IsFullThreadDevice()))
    {
        neighbor = Get<Mle::MleRouter>().GetRxOnlyNeighborRouter(srcaddr);
    }

    // Source Address Filtering
    if (srcaddr.IsShort())
    {
        otLogDebgMac("Received frame from short address 0x%04x", srcaddr.GetShort());

        if (neighbor == NULL)
        {
            ExitNow(error = OT_ERROR_UNKNOWN_NEIGHBOR);
        }

        srcaddr.SetExtended(neighbor->GetExtAddress());
    }

    // Duplicate Address Protection
    if (srcaddr.GetExtended() == mExtAddress)
    {
        ExitNow(error = OT_ERROR_INVALID_SOURCE_ADDRESS);
    }

#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE

    // Source filter Processing.
    if (srcaddr.IsExtended())
    {
        // check if filtered out by whitelist or blacklist.
        SuccessOrExit(error = mFilter.Apply(srcaddr.GetExtended(), rssi));

        // override with the rssi in setting
        if (rssi != OT_MAC_FILTER_FIXED_RSS_DISABLED)
        {
            aDataIndication->mMpduLinkQuality = rssi;
        }
    }

#endif // OPENTHREAD_CONFIG_MAC_FILTER_ENABLE

    // Security Processing
    SuccessOrExit(error = ProcessReceiveSecurity(aDataIndication->mSecurity, neighbor));

    if (neighbor != NULL)
    {
#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE

        // make assigned rssi to take effect quickly
        if (rssi != OT_MAC_FILTER_FIXED_RSS_DISABLED)
        {
            neighbor->GetLinkInfo().Clear();
        }

#endif // OPENTHREAD_CONFIG_MAC_FILTER_ENABLE

        neighbor->GetLinkInfo().AddRss(GetNoiseFloor(), dataInd.GetRssi());

        if (dataInd.GetSecurityEnabled())
        {
            switch (neighbor->GetState())
            {
            case Neighbor::kStateValid:
                break;

            case Neighbor::kStateRestored:
            case Neighbor::kStateChildUpdateRequest:
                // Only accept a "MAC Data Request" frame from a child being restored.
                ExitNow(error = OT_ERROR_DROP);
                break;

            default:
                ExitNow(error = OT_ERROR_UNKNOWN_NEIGHBOR);
            }
        }
    }

    // Receive
    Get<MeshForwarder>().HandleReceivedFrame(dataInd);

    // Process Frame Pending
    Get<DataPollSender>().CheckFramePending(dataInd);

exit:

    if (error != OT_ERROR_NONE)
    {
        otLogInfoMac("Frame rx failed, error:%s", otThreadErrorToString(error));

        switch (error)
        {
        case OT_ERROR_UNKNOWN_NEIGHBOR:
            mCounters.mRxErrUnknownNeighbor++;
            break;

        case OT_ERROR_INVALID_SOURCE_ADDRESS:
            mCounters.mRxErrInvalidSrcAddr++;
            break;

        default:
            mCounters.mRxErrOther++;
            break;
        }
    }
}

extern "C" void otPlatMlmeCommStatusIndication(otInstance *aInstance, otCommStatusIndication *aCommStatusIndication)
{
    Instance *instance = static_cast<Instance *>(aInstance);

    VerifyOrExit(instance->IsInitialized());

    instance->Get<Mac>().ProcessCommStatusIndication(aCommStatusIndication);

exit:
    return;
}

void Mac::ProcessCommStatusIndication(otCommStatusIndication *aCommStatusIndication)
{
    otLogInfoMac("Mac Security Error 0x%02x", aCommStatusIndication->mStatus);

    switch (aCommStatusIndication->mStatus)
    {
    case OT_MAC_STATUS_COUNTER_ERROR:
        mCounters.mRxDuplicated++;
        break;

    default:
        mCounters.mRxErrSec++;
        break;
    }

    if (aCommStatusIndication->mSrcAddrMode == OT_MAC_ADDRESS_MODE_SHORT)
    {
        uint16_t  srcAddr = Encoding::LittleEndian::ReadUint16(aCommStatusIndication->mSrcAddr);
        Neighbor *neighbor;
        otDumpDebgMac("From: ", aCommStatusIndication->mSrcAddr, 2);
        if ((neighbor = Get<Mle::MleRouter>().GetNeighbor(srcAddr)) != NULL)
        {
            uint8_t buffer[128];
            uint8_t len;
            otLogWarnMac("Rejected frame from neighbor %x", srcAddr);
            otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, neighbor->GetDeviceTableIndex(), &len, buffer);
            otDumpDebgMac("DeviceDesc", buffer, len);
            otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_KEY_TABLE, aCommStatusIndication->mSecurity.mKeyIndex, &len,
                          buffer);
            otDumpDebgMac("KeyDesc", buffer, len);
        }
    }
    else if (aCommStatusIndication->mSrcAddrMode == OT_MAC_ADDRESS_MODE_EXT)
    {
        otDumpDebgMac("From: ", aCommStatusIndication->mSrcAddr, 8);
    }

    if (aCommStatusIndication->mSecurity.mSecurityLevel > 0)
    {
        otLogDebgMac("Security Level: 0x%02x", aCommStatusIndication->mSecurity.mSecurityLevel);
        otLogDebgMac("Key Id Mode: 0x%02x", aCommStatusIndication->mSecurity.mKeyIdMode);
        otLogDebgMac("Key Index: 0x%02x", aCommStatusIndication->mSecurity.mKeyIndex);
        otDumpDebgMac("Key Source: ", aCommStatusIndication->mSecurity.mKeySource, 8);
    }
}

extern "C" void otPlatMlmePollIndication(otInstance *aInstance, otPollIndication *aPollIndication)
{
    Instance *instance = static_cast<Instance *>(aInstance);

    VerifyOrExit(instance->IsInitialized());
    VerifyOrExit(aPollIndication);

    instance->Get<Mac>().ProcessPollIndication(aPollIndication);

exit:
    return;
}

void Mac::ProcessPollIndication(otPollIndication *aPollIndication)
{
#if OPENTHREAD_FTD
    RxPoll &pollInd = static_cast<RxPoll &>(*aPollIndication);
    Get<DataPollHandler>().HandleDataPoll(pollInd);
#else
    OT_UNUSED_VARIABLE(aPollIndication);
#endif
}

void Mac::SetPcapCallback(otLinkPcapCallback aPcapCallback, void *aCallbackContext)
{
    (void)aPcapCallback;
    (void)aCallbackContext;
}

bool Mac::IsPromiscuous(void)
{
    uint8_t len;
    uint8_t promiscuous;

    otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_PROMISCUOUS_MODE, 0, &len, &promiscuous);
    assert(len == 1);

    return promiscuous;
}

void Mac::SetPromiscuous(bool aPromiscuous)
{
    uint8_t promiscuous = aPromiscuous ? 1 : 0;

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_PROMISCUOUS_MODE, 0, 1, &promiscuous);
}

void Mac::FillMacCountersTlv(NetworkDiagnostic::MacCountersTlv &aMacCounters) const
{
    aMacCounters.SetIfInUnknownProtos(0);
    aMacCounters.SetIfInErrors(mCounters.mRxErrUnknownNeighbor + mCounters.mRxErrInvalidSrcAddr + mCounters.mRxErrSec +
                               mCounters.mRxErrOther);
    aMacCounters.SetIfOutErrors(mCounters.mTxErrBusyChannel);
    aMacCounters.SetIfInUcastPkts(mCounters.mRxUnicast);
    aMacCounters.SetIfInBroadcastPkts(mCounters.mRxBroadcast);
    aMacCounters.SetIfInDiscards(0);
    aMacCounters.SetIfOutUcastPkts(mCounters.mTxUnicast);
    aMacCounters.SetIfOutBroadcastPkts(mCounters.mTxBroadcast);
    aMacCounters.SetIfOutDiscards(mCounters.mTxErrAbort);
}

void Mac::ResetCounters(void)
{
    memset(&mCounters, 0, sizeof(mCounters));
}

uint8_t Mac::GetValidMsduHandle(void)
{
    while (true)
    {
        mNextMsduHandle++;

        // Invalid Msdu
        if (mNextMsduHandle == 0)
            continue;

        // Msdu in use by direct frame
        if (mNextMsduHandle == mDirectMsduHandle)
            continue;
#if OPENTHREAD_FTD
        // Msdu in use by indirect frame
        if (Get<DataPollHandler>().GetFrameCache(mNextMsduHandle))
            continue;
#endif
        break;
    }

    otLogDebgMac("Allocated MSDU Handle %x", mNextMsduHandle);
    return mNextMsduHandle;
}

otError Mac::Start()
{
    otError error  = OT_ERROR_NONE;
    uint8_t buf[8] = {0, 0, 0, 0, 0, 0, 0, 0xFF};

    SuccessOrExit(error = otPlatMlmeReset(&GetInstance(), true));

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_DEFAULT_KEY_SOURCE, 0, 8, buf);

    buf[0] = 1; // Security Enabled
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_SECURITY_ENABLED, 0, 1, buf);

    // highest timeout for indirect transmissions (in units of aBaseSuperframeDuration)
    Encoding::LittleEndian::WriteUint16(0xFFFF, buf);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_TRANSACTION_PERSISTENCE_TIME, 0, 2, buf);

    // Match PiB to current MAC settings
    otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &mChannel);

    Encoding::LittleEndian::WriteUint16(mPanId, buf);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_PAN_ID, 0, 2, buf);

    Encoding::LittleEndian::WriteUint16(mShortAddress, buf);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_SHORT_ADDRESS, 0, 2, buf);

    CopyReversedExtAddr(mExtAddress, buf);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_IEEE_ADDRESS, 0, 8, buf);

    SetFrameCounter(Get<KeyManager>().GetCachedMacFrameCounter());

    if (mBeaconsEnabled)
    {
        BuildBeacon();
    }

    BuildSecurityTable();

exit:
    return error;
}

otError Mac::Stop()
{
    return otPlatMlmeReset(&GetInstance(), true);
}

uint32_t Mac::GetFrameCounter(void)
{
    uint8_t  leArray[4];
    uint32_t frameCounter;
    uint8_t  len;

    otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_FRAME_COUNTER, 0, &len, leArray);
    assert(len == 4);

    frameCounter = Encoding::LittleEndian::ReadUint32(leArray);

    return frameCounter;
}

void Mac::SetFrameCounter(uint32_t aFrameCounter)
{
    uint8_t leArray[4];

    Encoding::LittleEndian::WriteUint32(aFrameCounter, leArray);

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_FRAME_COUNTER, 0, 4, leArray);
}

const char *Mac::OperationToString(Operation aOperation)
{
    const char *retval = "";

    switch (aOperation)
    {
    case kOperationIdle:
        retval = "Idle";
        break;

    case kOperationActiveScan:
        retval = "ActiveScan";
        break;

    case kOperationEnergyScan:
        retval = "EnergyScan";
        break;

    case kOperationTransmitDataDirect:
        retval = "TransmitDataDirect";
        break;

    case kOperationTransmitDataIndirect:
        retval = "TransmitDataIndirect";
        break;
    }

    return retval;
}

int8_t Mac::GetNoiseFloor(void)
{
    return otPlatRadioGetReceiveSensitivity(&GetInstance());
}

otError FullAddr::GetAddress(Address &aAddress) const
{
    otError error = OT_ERROR_NONE;

    switch (mAddressMode)
    {
    case OT_MAC_ADDRESS_MODE_NONE:
        aAddress.SetNone();
        break;
    case OT_MAC_ADDRESS_MODE_SHORT:
        aAddress.SetShort(Encoding::LittleEndian::ReadUint16(mAddress));
        break;
    case OT_MAC_ADDRESS_MODE_EXT:
        aAddress.SetExtended(mAddress, ExtAddress::kReverseByteOrder);
        break;
    default:
        error = OT_ERROR_INVALID_ARGS;
    }
    return error;
}

otError FullAddr::SetAddress(const Address &aAddress)
{
    otError error = OT_ERROR_NONE;

    switch (aAddress.GetType())
    {
    case Address::kTypeNone:
        mAddressMode = OT_MAC_ADDRESS_MODE_NONE;
        break;
    case Address::kTypeShort:
        mAddressMode = OT_MAC_ADDRESS_MODE_SHORT;
        Encoding::LittleEndian::WriteUint16(aAddress.GetShort(), mAddress);
        break;
    case Address::kTypeExtended:
        mAddressMode = OT_MAC_ADDRESS_MODE_EXT;
        aAddress.GetExtended().CopyTo(mAddress, ExtAddress::kReverseByteOrder);
        break;
    default:
        error = OT_ERROR_INVALID_ARGS;
        break;
    }
    return error;
}

otError FullAddr::SetAddress(ShortAddress aShortAddress)
{
    otError error = OT_ERROR_NONE;

    mAddressMode = OT_MAC_ADDRESS_MODE_SHORT;
    Encoding::LittleEndian::WriteUint16(aShortAddress, mAddress);

    return error;
}

otError FullAddr::SetAddress(ExtAddress aExtAddress)
{
    otError error = OT_ERROR_NONE;

    mAddressMode = OT_MAC_ADDRESS_MODE_EXT;
    aExtAddress.CopyTo(mAddress, ExtAddress::kReverseByteOrder);

    return error;
}

otError Mac::SetEnabled(bool aEnable)
{
    VerifyOrExit(mEnabled != aEnable);
    mEnabled = aEnable;

    if (mEnabled)
        Start();
    else
        otPlatMlmeReset(&GetInstance(), true);

exit:
    return OT_ERROR_NONE;
}

extern "C" otError otPlatRadioGetTransmitPower(otInstance *aInstance, int8_t *aPower)
{
    uint8_t len;

    return otPlatMlmeGet(aInstance, OT_PIB_PHY_TRANSMIT_POWER, 0, &len, reinterpret_cast<uint8_t *>(aPower));
}

extern "C" otError otPlatRadioSetTransmitPower(otInstance *aInstance, int8_t aPower)
{
    // Bound to 6 bit signed twos compliment as defined in IEEE 802.15.4
    aPower = aPower > 0x3E ? 0x3E : aPower;
    aPower = aPower < -0x3F ? -0x3F : aPower;
    return otPlatMlmeSet(aInstance, OT_PIB_PHY_TRANSMIT_POWER, 0, 1, reinterpret_cast<uint8_t *>(&aPower));
}

} // namespace Mac
} // namespace ot

#endif // OPENTHREAD_CONFIG_USE_EXTERNAL_MAC
