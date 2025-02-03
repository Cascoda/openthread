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

#include <openthread/random_noncrypto.h>

#include "common/array.hpp"
#include "common/as_core_type.hpp"
#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/encoding.hpp"
#include "common/instance.hpp"
#include "common/locator.hpp"
#include "common/locator_getters.hpp"
#include "common/notifier.hpp"
#include "common/random.hpp"
#include "common/string.hpp"
#include "crypto/aes_ccm.hpp"
#include "crypto/sha256.hpp"
#include "mac/mac_frame.hpp"
#include "thread/child_table.hpp"
#include "thread/mle_router.hpp"
#include "thread/thread_netif.hpp"

using ot::Encoding::BigEndian::HostSwap64;

namespace ot {
namespace Mac {

RegisterLogModule("Mac");

const otExtAddress Mac::sMode2ExtAddress = {
    {0x35, 0x06, 0xfe, 0xb8, 0x23, 0xd4, 0x87, 0x12},
};

const otExtendedPanId Mac::sExtendedPanidInit = {
    {0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0xca, 0xfe},
};

const char Mac::sNetworkNameInit[] = "OpenThread";

#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
const char Mac::sDomainNameInit[] = "DefaultDomain";
#endif

Mac::Mac(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mOperation(kOperationIdle)
    , mPanId(kPanIdBroadcast)
    , mPendingOperations(0)
    , mChannel(OPENTHREAD_CONFIG_DEFAULT_CHANNEL)
    , mNextMsduHandle(1)
    , mDynamicKeyIndex(0)
    , mMode2DevHandle(0)
    , mSupportedChannelMask(Radio::kSupportedChannels)
    , mDeviceCurrentKeys()
    , mScanChannels(0)
    , mScanDuration(0)
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    , mCslTxFireTime(TimeMilli::kMaxDuration)
#endif
    , mActiveScanHandler(nullptr) // Initialize `mActiveScanHandler` and `mEnergyScanHandler` union
    , mScanHandlerContext(nullptr)
    , mLinks(aInstance)
#if OPENTHREAD_CONFIG_MULTI_RADIO
    , mTxError(kErrorNone)
#endif
{
    ExtAddress extAddress;
    GenerateExtAddress(&extAddress);

    static const otMacKey sMode2Key = {
        {0x78, 0x58, 0x16, 0x86, 0xfd, 0xb4, 0x58, 0x0f, 0xb0, 0x92, 0x54, 0x6a, 0xec, 0xbd, 0x15, 0x66}};

    SetEnabled(true);
    mLinks.Enable();

    Get<KeyManager>().UpdateKeyMaterial();
    SetExtendedPanId(AsCoreType(&sExtendedPanidInit));
    IgnoreError(SetNetworkName(sNetworkNameInit));
#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
    IgnoreError(SetDomainName(sDomainNameInit));
#endif
    SetPanId(mPanId);
    SetExtAddress(extAddress);
    mCcaSuccessRateTracker.Clear();
    ResetCounters();

    mMode2KeyMaterial.SetFrom(AsCoreType(&sMode2Key));
}

Error Mac::ActiveScan(uint32_t aScanChannels, uint16_t aScanDuration, ActiveScanHandler aHandler, void *aContext)
{
    Error error;

    mActiveScanHandler  = aHandler;
    mScanHandlerContext = aContext;

    SuccessOrExit(error = Scan(kOperationActiveScan, aScanChannels, aScanDuration));

exit:
    if (kErrorNone != error)
    {
        mActiveScanHandler = nullptr;
    }

    return error;
}

Error Mac::EnergyScan(uint32_t aScanChannels, uint16_t aScanDuration, EnergyScanHandler aHandler, void *aContext)
{
    Error error;

    mEnergyScanHandler  = aHandler;
    mScanHandlerContext = aContext;

    SuccessOrExit(error = Scan(kOperationEnergyScan, aScanChannels, aScanDuration));

exit:
    if (kErrorNone != error)
    {
        mEnergyScanHandler = nullptr;
    }

    return error;
}

Error Mac::Scan(Operation aScanOperation, uint32_t aScanChannels, uint16_t aScanDuration)
{
    Error   error        = kErrorNone;
    uint8_t scanDuration = 0; // The scan duration as defined by the 802.15.4 spec as being
                              // log2(aScanDuration/(aBaseSuperframeDuration * aSymbolPeriod))

    VerifyOrExit(mEnabled, error = kErrorInvalidState);
    VerifyOrExit(!IsScanInProgress(), error = kErrorBusy);

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
    return IsActiveOrPending(kOperationActiveScan);
}

bool Mac::IsEnergyScanInProgress(void)
{
    return IsActiveOrPending(kOperationEnergyScan);
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
        mActiveScanHandler(NULL, mScanHandlerContext);
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
            mEnergyScanHandler(&result, mScanHandlerContext);
        }
        mEnergyScanHandler(NULL, mScanHandlerContext);
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

    ActiveScanResult result;
    SuccessOrExit(ConvertBeaconToActiveScanResult(aBeaconNotify, result));

    mActiveScanHandler(&result, mScanHandlerContext);
exit:
    return;
}

Error Mac::ConvertBeaconToActiveScanResult(const otBeaconNotify *aBeaconNotify, ActiveScanResult &aResult)
{
    Error                error         = kErrorNone;
    const BeaconPayload *beaconPayload = nullptr;

    memset(&aResult, 0, sizeof(aResult));

    VerifyOrExit(aBeaconNotify != nullptr, error = kErrorInvalidArgs);
    VerifyOrExit(aBeaconNotify->mPanDescriptor.Coord.mAddressMode == OT_MAC_ADDRESS_MODE_EXT, error = kErrorParse);

    memcpy(&aResult.mExtAddress, aBeaconNotify->mPanDescriptor.Coord.mAddress, sizeof(aResult.mExtAddress));
    aResult.mPanId   = Encoding::LittleEndian::ReadUint16(aBeaconNotify->mPanDescriptor.Coord.mPanId);
    aResult.mChannel = aBeaconNotify->mPanDescriptor.LogicalChannel;
    aResult.mRssi    = aBeaconNotify->mPanDescriptor.LinkQuality;
    aResult.mLqi     = aBeaconNotify->mPanDescriptor.LinkQuality;

    beaconPayload = reinterpret_cast<const BeaconPayload *>(aBeaconNotify->mSdu);

    if ((aBeaconNotify->mSduLength >= sizeof(*beaconPayload)) && beaconPayload->IsValid())
    {
        aResult.mVersion    = beaconPayload->GetProtocolVersion();
        aResult.mIsJoinable = beaconPayload->IsJoiningPermitted();
        aResult.mIsNative   = beaconPayload->IsNative();
        IgnoreError(AsCoreType(&aResult.mNetworkName).Set(beaconPayload->GetNetworkName()));
        VerifyOrExit(IsValidUtf8String(aResult.mNetworkName.m8), error = kErrorParse);
        aResult.mExtendedPanId = beaconPayload->GetExtendedPanId();
    }
    else
    {
        error = kErrorParse;
    }

exit:
    return error;
}

void Mac::ReportActiveScanResult(const otBeaconNotify *aBeacon)
{
    VerifyOrExit(mActiveScanHandler != nullptr);

    if (aBeacon == nullptr)
    {
        mActiveScanHandler(nullptr, mScanHandlerContext);
    }
    else
    {
        ActiveScanResult result;

        SuccessOrExit(ConvertBeaconToActiveScanResult(aBeacon, result));
        mActiveScanHandler(&result, mScanHandlerContext);
    }

exit:
    return;
}

void Mac::SetRxOnWhenIdle(bool aRxOnWhenIdle)
{
    VerifyOrExit(mRxOnWhenIdle != aRxOnWhenIdle);
    mRxOnWhenIdle = aRxOnWhenIdle;

    mLinks.SetRxOnWhenBackoff(mRxOnWhenIdle);

exit:
    return;
}

Error Mac::SendDataPoll(otPollRequest &aPollReq)
{
    Error error = kErrorNone;

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

Error Mac::SetPanChannel(uint8_t aChannel)
{
    Error   error      = kErrorNone;
    uint8_t oldChannel = GetCurrentChannel();

    VerifyOrExit(mSupportedChannelMask.ContainsChannel(aChannel), error = kErrorInvalidArgs);
    mChannel = aChannel;

    VerifyOrExit(!mUseTempRxChannel && !mUseTempTxChannel);
    VerifyOrExit(oldChannel != mChannel);

    error = otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &mChannel);
    mCcaSuccessRateTracker.Clear();

exit:
    return error;
}

Error Mac::SetTemporaryChannel(uint8_t aChannel)
{
    Error   error      = kErrorNone;
    uint8_t newChannel = aChannel;
    uint8_t oldChannel = GetCurrentChannel();

    mUseTempRxChannel = true;
    mTempRxChannel    = newChannel;

    VerifyOrExit(newChannel != oldChannel);

    VerifyOrExit(mSupportedChannelMask.ContainsChannel(aChannel), error = kErrorInvalidArgs);

    VerifyOrExit(error = otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &newChannel));

exit:
    return error;
}

Error Mac::SetTempTxChannel(TxFrame &aTxFrame)
{
    Error   error      = kErrorNone;
    uint8_t newChannel = aTxFrame.GetChannel();
    uint8_t oldChannel = GetCurrentChannel();

    mUseTempTxChannel = true;
    mTempTxChannel    = newChannel;

    VerifyOrExit(newChannel != oldChannel);

    VerifyOrExit(mSupportedChannelMask.ContainsChannel(newChannel), error = kErrorInvalidArgs);

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

Error Mac::ClearTemporaryChannel()
{
    Error   error      = kErrorNone;
    uint8_t curChannel = GetCurrentChannel();
    uint8_t newChannel;

    mUseTempRxChannel = false;
    newChannel        = GetCurrentChannel();

    if (newChannel != curChannel)
        VerifyOrExit(error = otPlatMlmeSet(&GetInstance(), OT_PIB_PHY_CURRENT_CHANNEL, 0, 1, &newChannel));

exit:
    return error;
}

Error Mac::ClearTempTxChannel()
{
    Error   error      = kErrorNone;
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
    VerifyOrExit(newMask != mSupportedChannelMask, Get<Notifier>().SignalIfFirst(kEventSupportedChannelMaskChanged));

    mSupportedChannelMask = newMask;
    Get<Notifier>().Signal(kEventSupportedChannelMaskChanged);

exit:
    return;
}

Error Mac::SetNetworkName(const char *aNetworkName)
{
    return SignalNetworkNameChange(mNetworkName.Set(aNetworkName));
}

Error Mac::SetNetworkName(const NameData &aNameData)
{
    return SignalNetworkNameChange(mNetworkName.Set(aNameData));
}

Error Mac::SignalNetworkNameChange(Error aError)
{
    switch (aError)
    {
    case kErrorNone:
        Get<Notifier>().Signal(kEventThreadNetworkNameChanged);
        BuildBeacon();
        break;

    case kErrorAlready:
        Get<Notifier>().SignalIfFirst(kEventThreadNetworkNameChanged);
        aError = kErrorNone;
        BuildBeacon();
        break;

    default:
        break;
    }

    return aError;
}

#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
Error Mac::SetDomainName(const char *aNameString)
{
    Error error = mDomainName.Set(aNameString);

    return (error == kErrorAlready) ? kErrorNone : error;
}

Error Mac::SetDomainName(const NameData &aNameData)
{
    Error error = mDomainName.Set(aNameData);

    return (error == kErrorAlready) ? kErrorNone : error;
}
#endif // (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)

Error Mac::SetPanId(PanId aPanId)
{
    Error error = kErrorNone;

    VerifyOrExit(mPanId != aPanId);
    mPanId = aPanId;

    mLinks.SetPanId(mPanId);
    BuildSecurityTable();

exit:
    return error;
}

Error Mac::SetExtendedPanId(const ExtendedPanId &aExtendedPanId)
{
    IgnoreError(Get<Notifier>().Update(mExtendedPanId, aExtendedPanId, kEventThreadExtPanIdChanged));
    BuildBeacon();
    return kErrorNone;
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

void Mac::RequestDirectFrameTransmission(void)
{
    VerifyOrExit(IsEnabled());
    VerifyOrExit(!IsActiveOrPending(kOperationTransmitDataDirect));

    StartOperation(kOperationTransmitDataDirect);

exit:
    return;
}

void Mac::RequestIndirectFrameTransmission(void)
{
    VerifyOrExit(IsEnabled());
    VerifyOrExit(!IsActiveOrPending(kOperationTransmitDataIndirect));

    StartOperation(kOperationTransmitDataIndirect);

exit:
    return;
}

#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
void Mac::RequestCslFrameTransmission(uint32_t aDelay)
{
    VerifyOrExit(mEnabled);

    mCslTxFireTime = TimerMilli::GetNow() + aDelay;

    StartOperation(kOperationTransmitDataCsl);

exit:
    return;
}
#endif

Error Mac::PurgeIndirectFrame(uint8_t aMsduHandle)
{
    Error error = otPlatMcpsPurge(&GetInstance(), aMsduHandle);
    LogDebg("Purged handle %x with error %s", aMsduHandle, otThreadErrorToString(error));
    return error;
}

bool Mac::IsActiveOrPending(Operation aOperation) const
{
    return (mOperation == aOperation) || IsPending(aOperation);
}

void Mac::StartOperation(Operation aOperation)
{
    if (aOperation != kOperationIdle)
    {
        SetPending(aOperation);

        LogDebg("Request to start operation \"%s\"", OperationToString(aOperation));

        if (!mEnabled)
        {
            ClearPending(kOperationActiveScan);
            ClearPending(kOperationEnergyScan);
            ClearPending(kOperationTransmitDataDirect);
            ClearPending(kOperationTransmitDataIndirect);
            ExitNow();
        }
    }

    VerifyOrExit(mOperation == kOperationIdle);

    if (IsPending(kOperationActiveScan))
    {
        ClearPending(kOperationActiveScan);
        mOperation = kOperationActiveScan;
        HandleBeginScan();
    }
    else if (IsPending(kOperationEnergyScan))
    {
        ClearPending(kOperationEnergyScan);
        mOperation = kOperationEnergyScan;
        HandleBeginScan();
    }
    else if (IsPending(kOperationTransmitDataDirect))
    {
        ClearPending(kOperationTransmitDataDirect);
        mOperation = kOperationTransmitDataDirect;
        HandleBeginDirect();
    }
#if OPENTHREAD_FTD
    else if (IsPending(kOperationTransmitDataIndirect))
    {
        ClearPending(kOperationTransmitDataIndirect);
        mOperation = kOperationTransmitDataIndirect;
        HandleBeginIndirect();
    }
#endif

    if (mOperation != kOperationIdle)
    {
        LogDebg("Starting operation \"%s\"", OperationToString(mOperation));
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
    LogDebg("Finishing operation \"%s\"", OperationToString(mOperation));

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

    if (Get<KeyManager>().GetSecurityPolicy().mBeaconsEnabled)
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
Error Mac::BuildDeviceDescriptor(const ExtAddress &aExtAddress,
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

    LogDebg("Built device descriptor at index %d", aIndex);
    LogDebg("Short Address: 0x%04x", shortAddr);
    LogDebg("Ext Address: %02x%02x%02x%02x%02x%02x%02x%02x", deviceDescriptor.mExtAddress[0],
            deviceDescriptor.mExtAddress[1], deviceDescriptor.mExtAddress[2], deviceDescriptor.mExtAddress[3],
            deviceDescriptor.mExtAddress[4], deviceDescriptor.mExtAddress[5], deviceDescriptor.mExtAddress[6],
            deviceDescriptor.mExtAddress[7]);
    LogDebg("Frame Counter: 0x%08x", aFrameCounter);

    return otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, aIndex, sizeof(deviceDescriptor),
                         reinterpret_cast<uint8_t *>(&deviceDescriptor));
}

Error Mac::BuildDeviceDescriptor(Neighbor &aNeighbor, uint8_t &aIndex)
{
    Error   error     = kErrorNone;
    int32_t keyOffset = 0, keyNum = 0;
    uint8_t reps = 1;

    keyNum = 1 + aNeighbor.GetKeySequence() - Get<KeyManager>().GetCurrentKeySequence();
    VerifyOrExit(keyNum >= 0 && keyNum <= 2, error = kErrorSecurity);

#if !OPENTHREAD_CONFIG_EXTERNAL_MAC_SHARED_DD
    reps      = 3;
    keyOffset = keyNum;
#endif

    mDeviceCurrentKeys[aIndex / reps] = keyNum;

    aNeighbor.SetDeviceTableIndex(aIndex + static_cast<uint8_t>(keyOffset));

    for (int i = 0; i < reps; i++)
    {
        uint32_t fc = aNeighbor.GetLinkFrameCounters().Get();

        if (i < keyOffset) // No way to track old FCs or modify them in higher layer so receiving to old key is
                           // inherently unsafe
        {
            fc = 0xFFFFFFFF;
        }
        error = BuildDeviceDescriptor(aNeighbor.GetExtAddress(), fc, mPanId, aNeighbor.GetRloc16(), aIndex);
        LogDebg("Key Sequence Number: %d", aNeighbor.GetKeySequence());
        VerifyOrExit(error == kErrorNone);
        aIndex += 1;
    }

exit:
    if (error)
    {
        LogDebg("BuildDeviceDescriptor error %s", otThreadErrorToString(error));
    }
    return error;
}

#if OPENTHREAD_FTD
Error Mac::BuildRouterDeviceDescriptors(uint8_t &aDevIndex, uint8_t aIgnoreRouterId)
{
    Error error = kErrorNone;

    for (Child &child : Get<ChildTable>().Iterate(Child::kInStateValidOrRestoring))
    {
        LogDebg("Building Child DD...");
        BuildDeviceDescriptor(child, aDevIndex);
        mActiveNeighborCount++;
    }

    for (Router &router : Get<RouterTable>().Iterate())
    {
        if (router.GetRouterId() == aIgnoreRouterId)
            continue; // Ignore self

        if (Get<NeighborTable>().FindNeighbor(router.GetRloc16()) == NULL)
            continue; // Ignore non-neighbors

        LogDebg("Building Router DD...");
        error = BuildDeviceDescriptor(router, aDevIndex);
        VerifyOrExit(error == kErrorNone);
        mActiveNeighborCount++;
    }

exit:
    return error;
}
#endif

void Mac::CacheDevice(Neighbor &aNeighbor)
{
    uint8_t               len;
    uint8_t               index = aNeighbor.GetDeviceTableIndex();
    otPibDeviceDescriptor deviceDesc;
    ExtAddress            addr;
    Error                 error = kErrorNone;

    error =
        otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, index, &len, reinterpret_cast<uint8_t *>(&deviceDesc));
    VerifyOrExit(error == kErrorNone);
    OT_ASSERT(len == sizeof(deviceDesc));

    CopyReversedExtAddr(deviceDesc.mExtAddress, addr);
    VerifyOrExit(memcmp(&addr, &(aNeighbor.GetExtAddress()), sizeof(addr)) == 0);

    aNeighbor.GetLinkFrameCounters().Set(Encoding::LittleEndian::ReadUint32(deviceDesc.mFrameCounter));

exit:
    if (error != kErrorNone)
    {
        // Fall back to caching entire device table
        CacheDeviceTable();
    }
}

Error Mac::UpdateDevice(Neighbor &aNeighbor)
{
    uint8_t               len;
    uint8_t               index = aNeighbor.GetDeviceTableIndex();
    int32_t               keyNum;
    uint8_t               reps = 1;
    otPibDeviceDescriptor deviceDesc;
    ExtAddress            addr;
    Error                 error = kErrorNone;

    LogDebg("Updating device.");
#if !OPENTHREAD_CONFIG_EXTERNAL_MAC_SHARED_DD
    reps = 3;
#endif

    VerifyOrExit(aNeighbor.IsStateValidOrRestoring(), error = kErrorNotFound);

    keyNum = 1 + aNeighbor.GetKeySequence() - Get<KeyManager>().GetCurrentKeySequence();
    LogDebg("Key Sequence Number: %d", aNeighbor.GetKeySequence());
    VerifyOrExit(keyNum >= 0 && keyNum <= 2, error = kErrorSecurity);

    mDeviceCurrentKeys[index / reps] = keyNum;

    error =
        otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, index, &len, reinterpret_cast<uint8_t *>(&deviceDesc));
    VerifyOrExit(error == kErrorNone);
    OT_ASSERT(len == sizeof(deviceDesc));

    CopyReversedExtAddr(deviceDesc.mExtAddress, addr);
    VerifyOrExit(memcmp(&addr, &(aNeighbor.GetExtAddress()), sizeof(addr)) == 0, error = kErrorNotFound);

    Encoding::LittleEndian::WriteUint32(aNeighbor.GetLinkFrameCounters().Get(), deviceDesc.mFrameCounter);
    error =
        otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, index, len, reinterpret_cast<uint8_t *>(&deviceDesc));

    BuildKeyTable();

exit:
    if (error)
    {
        LogDebg("UpdateDevice error: %s", otThreadErrorToString(error));
    }
    return error;
}

void Mac::CacheDeviceTable()
{
    uint8_t len;
    uint8_t numDevices;

    otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE_ENTRIES, 0, &len, &numDevices);
    OT_ASSERT(len == 1);

    for (uint8_t i = 0; i < numDevices; i++)
    {
        otPibDeviceDescriptor deviceDesc;
        Neighbor *            neighbor;
        Address               addr;

        otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, i, &len, reinterpret_cast<uint8_t *>(&deviceDesc));
        OT_ASSERT(len == sizeof(deviceDesc));

        addr.SetShort(Encoding::LittleEndian::ReadUint16(deviceDesc.mShortAddress));

        if (addr.GetShort() == kShortAddrInvalid)
        {
            addr.SetExtended(deviceDesc.mExtAddress, ExtAddress::kReverseByteOrder);
        }

        neighbor = Get<NeighborTable>().FindNeighbor(addr);

        if (neighbor != NULL)
        {
            neighbor->GetLinkFrameCounters().Set(Encoding::LittleEndian::ReadUint32(deviceDesc.mFrameCounter));
        }
    }
}

void Mac::BuildJoinerKeyDescriptor(uint8_t aIndex)
{
#if OPENTHREAD_CONFIG_JOINER_ENABLE
    otKeyTableEntry keyTableEntry;
    ExtAddress      counterpart;

    memset(&keyTableEntry, 0, sizeof(keyTableEntry));
    memcpy(keyTableEntry.mKey, &Get<KeyManager>().GetKek(), sizeof(keyTableEntry.mKey));
    keyTableEntry.mKeyIdLookupListEntries = 1;
    keyTableEntry.mKeyUsageListEntries    = 1;
    keyTableEntry.mKeyDeviceListEntries   = 1;

    keyTableEntry.mKeyIdLookupDesc[0].mLookupDataSizeCode = OT_MAC_LOOKUP_DATA_SIZE_CODE_9_OCTETS;
    Get<MeshCoP::Joiner>().GetCounterpartAddress(counterpart);
    CopyReversedExtAddr(counterpart, &(keyTableEntry.mKeyIdLookupDesc[0].mLookupData[1]));

    keyTableEntry.mKeyDeviceDesc[0].mDeviceDescriptorHandle = 0;

    keyTableEntry.mKeyUsageDesc[0].mFrameType = Frame::kFcfFrameData;

    LogDebg("Built joiner key descriptor at index %d", aIndex);
    LogDebg("Lookup Data: %02x%02x%02x%02x%02x%02x%02x%02x%02x", keyTableEntry.mKeyIdLookupDesc[0].mLookupData[0],
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

void Mac::BuildMainKeyDescriptors(uint8_t &aIndex)
{
    otKeyTableEntry keyTableEntry;
    uint32_t        keySequence = Get<KeyManager>().GetCurrentKeySequence() - 1;
    uint8_t         ddReps      = 3;

#if OPENTHREAD_CONFIG_EXTERNAL_MAC_SHARED_DD
    ddReps = 1;
#endif

    VerifyOrExit(mActiveNeighborCount > 0);
    memset(&keyTableEntry, 0, sizeof(keyTableEntry));

    keyTableEntry.mKeyIdLookupListEntries = 1;
    keyTableEntry.mKeyUsageListEntries    = 2;
    keyTableEntry.mKeyDeviceListEntries   = mActiveNeighborCount;

    keyTableEntry.mKeyIdLookupDesc[0].mLookupDataSizeCode = OT_MAC_LOOKUP_DATA_SIZE_CODE_9_OCTETS;
    keyTableEntry.mKeyIdLookupDesc[0].mLookupData[8]      = 0xFF; // keyIndex || macDefaultKeySource

    keyTableEntry.mKeyUsageDesc[0].mFrameType      = Frame::kFcfFrameData;
    keyTableEntry.mKeyUsageDesc[1].mFrameType      = Frame::kFcfFrameMacCmd;
    keyTableEntry.mKeyUsageDesc[1].mCommandFrameId = Frame::kMacCmdDataRequest;

    for (int i = 0; i < 3; i++)
    {
        const KeyMaterial *key = &Get<KeyManager>().GetTemporaryMacKey(keySequence);
        memcpy(keyTableEntry.mKey, key, sizeof(keyTableEntry.mKey));
        keyTableEntry.mKeyIdLookupDesc[0].mLookupData[0] = (keySequence & 0x7F) + 1;

        for (int j = 0; j < mActiveNeighborCount; j++)
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

        LogDebg("Built Key at index %d", aIndex);
        for (int j = 0; j < mActiveNeighborCount; j++)
        {
            LogDebg("Device Desc handle %d, blacklisted %d", keyTableEntry.mKeyDeviceDesc[j].mDeviceDescriptorHandle,
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

void Mac::BuildMode2KeyDescriptor(uint8_t aIndex)
{
    otKeyTableEntry keyTableEntry;
    Key             key;

    memset(&keyTableEntry, 0, sizeof(keyTableEntry));

    mDynamicKeyIndex = aIndex;

    keyTableEntry.mKeyIdLookupListEntries = 1;
    keyTableEntry.mKeyUsageListEntries    = 1;
    keyTableEntry.mKeyDeviceListEntries   = 1;

    keyTableEntry.mKeyIdLookupDesc[0].mLookupDataSizeCode = OT_MAC_LOOKUP_DATA_SIZE_CODE_5_OCTETS;
    memset(keyTableEntry.mKeyIdLookupDesc[0].mLookupData, 0xFF, 5);

    keyTableEntry.mKeyUsageDesc[0].mFrameType     = Frame::kFcfFrameData;
    keyTableEntry.mKeyDeviceDesc[0].mUniqueDevice = true; // Assumed errata in thread spec says this should be false
    keyTableEntry.mKeyDeviceDesc[0].mDeviceDescriptorHandle = mMode2DevHandle;

    mMode2KeyMaterial.ExtractKey(key);
    memcpy(keyTableEntry.mKey, &key, sizeof(keyTableEntry.mKey));

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

    memcpy(keyTableEntry.mKey, &Get<KeyManager>().GetKek(), sizeof(keyTableEntry.mKey));

    LogDebg("Built joiner router key descriptor at index %d", mDynamicKeyIndex);
    LogDebg("Lookup Data: %02x%02x%02x%02x%02x%02x%02x%02x%02x", keyTableEntry.mKeyIdLookupDesc[0].mLookupData[0],
            keyTableEntry.mKeyIdLookupDesc[0].mLookupData[1], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[2],
            keyTableEntry.mKeyIdLookupDesc[0].mLookupData[3], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[4],
            keyTableEntry.mKeyIdLookupDesc[0].mLookupData[5], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[6],
            keyTableEntry.mKeyIdLookupDesc[0].mLookupData[7], keyTableEntry.mKeyIdLookupDesc[0].mLookupData[8]);

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_KEY_TABLE, mDynamicKeyIndex, sizeof(keyTableEntry),
                  reinterpret_cast<uint8_t *>(&keyTableEntry));

    mJoinerEntrustResponseRequested = true;
}

void Mac::BuildKeyTable()
{
    uint8_t keyIndex  = 0;
    bool    isJoining = false;

#if OPENTHREAD_CONFIG_JOINER_ENABLE
    isJoining = (Get<MeshCoP::Joiner>().GetState() == ot::MeshCoP::Joiner::kStateConnect);
#endif

    if (isJoining)
    {
#if OPENTHREAD_CONFIG_JOINER_ENABLE
        BuildJoinerKeyDescriptor(keyIndex++);
#endif
    }
    else
    {
        BuildMainKeyDescriptors(keyIndex);
    }
    BuildMode2KeyDescriptor(keyIndex++);

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_KEY_TABLE_ENTRIES, 0, 1, &keyIndex);
}

void Mac::BuildSecurityTable()
{
    ot::Mle::DeviceRole role                = Get<Mle::Mle>().GetRole();
    uint8_t             devIndex            = 0;
    uint8_t             nextHopForNeighbors = Mle::kInvalidRouterId;
    bool                isFFD               = (Get<Mle::Mle>().GetDeviceMode().IsFullThreadDevice());
    
#if OPENTHREAD_CONFIG_JOINER_ENABLE
    bool                isJoining           = false;
#endif

    mActiveNeighborCount = 0;
    LogDebg("Current KeySequenceNumber: %d", Get<KeyManager>().GetCurrentKeySequence());

#if OPENTHREAD_CONFIG_JOINER_ENABLE
    isJoining = (Get<MeshCoP::Joiner>().GetState() == ot::MeshCoP::Joiner::kStateConnect);
#endif

    // Cache the frame counters so that they remain correct after flushing device table
    CacheDeviceTable();

    // Note: The reason the router table is not specific to the router role is because
    // FFD children have one-way comms (rx-only) with neighboring routers so they must
    // maintain the device table for them. See TS:1.1.1 sec 4.7.7.4

    // The reason we don't check for role at all is because routers can have parent
    // candidates if they are reattaching to a better partition.

    if (Get<Mle::Mle>().GetParentCandidate().IsStateValidOrRestoring())
    {
        Router &parent = Get<Mle::Mle>().GetParentCandidate();
        LogDebg("Building Parent Candidate DD...");
        BuildDeviceDescriptor(parent, devIndex);
        mActiveNeighborCount++;
    }
    if (((role == ot::Mle::kRoleChild) || (role == ot::Mle::kRoleDetached)) &&
        Get<Mle::Mle>().GetParent().IsStateValidOrRestoring())
    {
        Router &parent = Get<Mle::Mle>().GetParent();
        LogDebg("Building Parent DD...");
        BuildDeviceDescriptor(parent, devIndex);
        mActiveNeighborCount++;
        nextHopForNeighbors = parent.GetRouterId();
    }
    if (isFFD)
    {
#if OPENTHREAD_FTD
        BuildRouterDeviceDescriptors(devIndex, nextHopForNeighbors);
#else
        OT_UNUSED_VARIABLE(nextHopForNeighbors);
#endif
    }

#if OPENTHREAD_CONFIG_JOINER_ENABLE
    if (role == ot::Mle::kRoleDisabled && isJoining)
    {
        ExtAddress counterpart;
        Get<MeshCoP::Joiner>().GetCounterpartAddress(counterpart);
        BuildDeviceDescriptor(counterpart, 0, mPanId, 0xFFFF, devIndex++);
    }
#endif

    // Set the mode 2 'device'
    mMode2DevHandle = devIndex++;
    BuildDeviceDescriptor(static_cast<const ExtAddress &>(sMode2ExtAddress), 0, 0xFFFF, 0xFFFF, mMode2DevHandle);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE_ENTRIES, 0, 1, &devIndex);

    BuildKeyTable();

    LogInfo("Built Security Table with %d devices", mActiveNeighborCount);
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
        keyManager.Increment154MacFrameCounter();
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
        OT_ASSERT(false);
    }

exit:
    return;
}

void Mac::HandleBeginDirect(void)
{
    TxFrames &txFrames  = mLinks.GetTxFrames();
    TxFrame & sendFrame = mDirectDataReq;
    TxFrame * frame     = nullptr;
    Error     error     = kErrorNone;
    Address   dstAddr;

    LogDebg("Mac::HandleBeginDirect");
    memset(&sendFrame, 0, sizeof(sendFrame));

    sendFrame.SetChannel(mChannel);
    txFrames.SetTxFrame(&sendFrame);

    frame = Get<MeshForwarder>().HandleFrameRequest(txFrames);
    if (frame == nullptr)
    {
        error = kErrorAbort;
    }

    SuccessOrExit(error);

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
        isJoining = (Get<MeshCoP::Joiner>().GetState() != ot::MeshCoP::Joiner::kStateIdle &&
                     Get<MeshCoP::Joiner>().GetState() != ot::MeshCoP::Joiner::kStateJoined);
#endif

        if (!isJoining)
        {
            // Hotswap the kek descriptor into keytable for joiner entrust response
            OT_ASSERT(sendFrame.mDst.mAddressMode == OT_MAC_ADDRESS_MODE_EXT);
            HotswapJoinerRouterKeyDescriptor(sendFrame.mDst.mAddress);
        }
    }

    sendFrame.GetDstAddr(dstAddr);

    error = SetTempTxChannel(sendFrame);
    OT_ASSERT(error == kErrorNone);
    LogDebg("calling otPlatRadioTransmit for direct");
    LogDebg("Sam %x; Dam %x; MH %x; DstAddr %s;", sendFrame.mSrcAddrMode, sendFrame.mDst.mAddressMode,
            sendFrame.mMsduHandle, dstAddr.ToString().AsCString());
    DumpDebg("Msdu", sendFrame.mMsdu, sendFrame.mMsduLength);
    mDirectAckRequested = sendFrame.GetAckRequest();
    sendFrame.GetDstAddr(mDirectDstAddress);
    error = otPlatMcpsDataRequest(&GetInstance(), &sendFrame);
    OT_ASSERT(error == kErrorNone);

exit:
    if (error != kErrorNone)
    {
        // If the sendFrame could not be prepared and the tx is being
        // aborted, forward the error back up.
        sendFrame.GetDstAddr(mDirectDstAddress);
        Get<MeshForwarder>().HandleSentFrame(sendFrame.GetAckRequest(), error, mDirectDstAddress);
    }

    return;
}

#if OPENTHREAD_FTD
void Mac::HandleBeginIndirect(void)
{
    TxFrame * frame     = nullptr;
    TxFrames &txFrames  = mLinks.GetTxFrames();
    TxFrame & sendFrame = mIndirectDataReq;
    Error     error     = kErrorNone;
    Address   dstAddr;

    LogDebg("Mac::HandleBeginIndirect");
    memset(&sendFrame, 0, sizeof(sendFrame));

    sendFrame.SetChannel(mChannel);
    txFrames.SetTxFrame(&sendFrame);
    frame = Get<DataPollHandler>().HandleFrameRequest(txFrames);
    if (frame == nullptr)
    {
        error = kErrorAbort;
    }

    SuccessOrExit(error);

    mCounters.mTxUnicast++;

    ProcessTransmitSecurity(sendFrame.mSecurity);
    sendFrame.mTxOptions |= OT_MAC_TX_OPTION_INDIRECT;
    sendFrame.mTxOptions |= OT_MAC_TX_OPTION_NS_SECURE_IND;

    sendFrame.GetDstAddr(dstAddr);
    LogDebg("calling otPlatRadioTransmit for indirect");
    LogDebg("Sam %x; Dam %x; MH %x; DstAddr %s;", sendFrame.mSrcAddrMode, sendFrame.mDst.mAddressMode,
            sendFrame.mMsduHandle, dstAddr.ToString().AsCString());
    DumpDebg("Msdu", sendFrame.mMsdu, sendFrame.mMsduLength);
    error = otPlatMcpsDataRequest(&GetInstance(), &sendFrame);

    OT_ASSERT(error == kErrorNone);
exit:
    LogDebg("HandleBeginIndirect: %s", otThreadErrorToString(error));
    return;
}
#endif

void Mac::HandleNotifierEvents(Events aEvents)
{
    if (aEvents.ContainsAny(kEventThreadKeySeqCounterChanged | kEventThreadChildAdded | kEventThreadChildRemoved |
                            kEventThreadRoleChanged))
    {
        BuildSecurityTable();
    }
}

extern "C" void otPlatMcpsDataConfirm(otInstance *aInstance, uint8_t aMsduHandle, Error aError)
{
    Instance *instance = static_cast<Instance *>(aInstance);
    VerifyOrExit(instance->IsInitialized());

    instance->Get<Mac>().TransmitDoneTask(aMsduHandle, aError);

exit:
    return;
}

Error Mac::ProcessTransmitStatus(Error aTransmitError)
{
    Error error      = aTransmitError;
    bool  ccaSuccess = true;

    switch (error)
    {
    case kErrorChannelAccessFailure:
        ccaSuccess = false;
        mCounters.mTxErrBusyChannel++;
    // fall through
    case kErrorNoAck:
    case kErrorNone:
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
        LogInfo("Converting error %s to ABORT", otThreadErrorToString(error));
        error = kErrorAbort;
        break;
    }

    return error;
}

void Mac::TransmitDoneTask(uint8_t aMsduHandle, Error aError)
{
    Error error = ProcessTransmitStatus(aError);

    LogDebg("TransmitDoneTask Called");

    if (error != kErrorNone)
    {
        LogDebg("Transmit Error: %s", otThreadErrorToString(aError));
    }

    if (aMsduHandle == mDirectMsduHandle)
    {
        if (aError == kErrorChannelAccessFailure)
        {
            // Failed without even hitting the air, retry silently.
            error = otPlatMcpsDataRequest(&GetInstance(), &mDirectDataReq);
            OT_ASSERT(error == kErrorNone);
            if (error != kErrorNone)
            {
                // If the frame could not be prepared and the tx is being
                // aborted, forward the error back up.
                Get<MeshForwarder>.HandleSentFrame(mDirectAckRequested, error, mDirectDstAddress);
            }
            return;
        }
        if (mJoinerEntrustResponseRequested)
        {
            // Restore the mode 2 key after sending the joiner entrust response
            mJoinerEntrustResponseRequested = false;
            BuildMode2KeyDescriptor(mDynamicKeyIndex);
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

Error Mac::ProcessReceiveSecurity(otSecSpec &aSecSpec, Neighbor *aNeighbor)
{
    Error       error = kErrorNone;
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
        VerifyOrExit(aNeighbor != nullptr, error = kErrorSecurity);

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
            LogCrit("Incorrect KeySequence passed through HardMac");
            ExitNow(error = kErrorSecurity);
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

#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2) && OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
#if OPENTHREAD_CONFIG_MULTI_RADIO
        if (aFrame.GetRadioType() == kRadioTypeIeee802154)
#endif
        {
            if ((frameCounter + 1) > aNeighbor->GetLinkAckFrameCounter())
            {
                aNeighbor->SetLinkAckFrameCounter(frameCounter + 1);
            }
        }
#endif

        if (keySequence > keyManager.GetCurrentKeySequence())
        {
            keyManager.SetCurrentKeySequence(keySequence);
        }
    }

exit:
    return error;
}

#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2
Error Mac::ProcessEnhAckSecurity(TxFrame &aTxFrame, RxFrame &aAckFrame)
{
    Error              error = kErrorSecurity;
    uint8_t            securityLevel;
    uint8_t            txKeyId;
    uint8_t            ackKeyId;
    uint8_t            keyIdMode;
    uint32_t           frameCounter;
    Address            srcAddr;
    Address            dstAddr;
    Neighbor *         neighbor   = nullptr;
    KeyManager &       keyManager = Get<KeyManager>();
    const KeyMaterial *macKey;

    VerifyOrExit(aAckFrame.GetSecurityEnabled(), error = kErrorNone);
    VerifyOrExit(aAckFrame.IsVersion2015());

    IgnoreError(aAckFrame.GetSecurityLevel(securityLevel));
    VerifyOrExit(securityLevel == Frame::kSecEncMic32);

    IgnoreError(aAckFrame.GetKeyIdMode(keyIdMode));
    VerifyOrExit(keyIdMode == Frame::kKeyIdMode1, error = kErrorNone);

    IgnoreError(aTxFrame.GetKeyId(txKeyId));
    IgnoreError(aAckFrame.GetKeyId(ackKeyId));

    VerifyOrExit(txKeyId == ackKeyId);

    IgnoreError(aAckFrame.GetFrameCounter(frameCounter));
    LogDebg("Rx security - Ack frame counter %u", frameCounter);

    IgnoreError(aAckFrame.GetSrcAddr(srcAddr));

    if (!srcAddr.IsNone())
    {
        neighbor = Get<NeighborTable>().FindNeighbor(srcAddr);
    }
    else
    {
        IgnoreError(aTxFrame.GetDstAddr(dstAddr));

        if (!dstAddr.IsNone())
        {
            // Get neighbor from destination address of transmitted frame
            neighbor = Get<NeighborTable>().FindNeighbor(dstAddr);
        }
    }

    if (!srcAddr.IsExtended() && neighbor != nullptr)
    {
        srcAddr.SetExtended(neighbor->GetExtAddress());
    }

    VerifyOrExit(srcAddr.IsExtended() && neighbor != nullptr);

    ackKeyId--;

    if (ackKeyId == (keyManager.GetCurrentKeySequence() & 0x7f))
    {
        macKey = &mLinks.GetSubMac().GetCurrentMacKey();
    }
    else if (ackKeyId == ((keyManager.GetCurrentKeySequence() - 1) & 0x7f))
    {
        macKey = &mLinks.GetSubMac().GetPreviousMacKey();
    }
    else if (ackKeyId == ((keyManager.GetCurrentKeySequence() + 1) & 0x7f))
    {
        macKey = &mLinks.GetSubMac().GetNextMacKey();
    }
    else
    {
        ExitNow();
    }

    if (neighbor->IsStateValid())
    {
        VerifyOrExit(frameCounter >= neighbor->GetLinkAckFrameCounter());
    }

    error = aAckFrame.ProcessReceiveAesCcm(srcAddr.GetExtended(), *macKey);
    SuccessOrExit(error);

    if (neighbor->IsStateValid())
    {
        neighbor->SetLinkAckFrameCounter(frameCounter + 1);
    }

exit:
    if (error != kErrorNone)
    {
        LogInfo("Frame tx attempt failed, error: Enh-ACK security check fail");
    }

    return error;
}
#endif // OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2

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
    Error     error = kErrorNone;
    bool      isFFD = Get<Mle::Mle>().GetDeviceMode().IsFullThreadDevice();

#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
    int8_t rssi = OT_MAC_FILTER_FIXED_RSS_DISABLED;
#endif // OPENTHREAD_CONFIG_MAC_FILTER_ENABLE

    OT_ASSERT(aDataIndication != NULL);

    dataInd.SetChannel(GetCurrentChannel());
    dataInd.GetSrcAddr(srcaddr);
    dataInd.GetDstAddr(dstaddr);
    neighbor = Get<NeighborTable>().FindNeighbor(srcaddr);

    if (dstaddr.IsBroadcast())
        mCounters.mRxBroadcast++;
    else
        mCounters.mRxUnicast++;

    if (isFFD)
    {
#if OPENTHREAD_FTD
        // Allow  multicasts from neighbor routers if FFD
        if (neighbor == NULL && dstaddr.IsBroadcast())
            neighbor = Get<NeighborTable>().FindRxOnlyNeighborRouter(srcaddr);
#endif
    }

    // Source Address Filtering
    if (srcaddr.IsShort())
    {
        LogDebg("Received frame from short address 0x%04x", srcaddr.GetShort());

        if (neighbor == NULL)
        {
            ExitNow(error = kErrorUnknownNeighbor);
        }

        srcaddr.SetExtended(neighbor->GetExtAddress());
    }

    // Duplicate Address Protection
    if (srcaddr.GetExtended() == GetExtAddress())
    {
        ExitNow(error = kErrorInvalidSourceAddress);
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
        neighbor->GetLinkInfo().SetCs(dataInd.GetCs());

        if (dataInd.GetSecurityEnabled())
        {
            switch (neighbor->GetState())
            {
            case Neighbor::kStateValid:
                break;

            case Neighbor::kStateRestored:
            case Neighbor::kStateChildUpdateRequest:
                // Only accept a "MAC Data Request" frame from a child being restored.
                ExitNow(error = kErrorDrop);
                break;

            default:
                ExitNow(error = kErrorUnknownNeighbor);
            }
        }
    }

    // Receive
    Get<MeshForwarder>().HandleReceivedFrame(dataInd);

    // Process Frame Pending
    Get<DataPollSender>().ProcessRxFrame(dataInd);

exit:

    if (error != kErrorNone)
    {
        LogInfo("Frame rx failed, error:%s", otThreadErrorToString(error));

        switch (error)
        {
        case kErrorUnknownNeighbor:
            mCounters.mRxErrUnknownNeighbor++;
            break;

        case kErrorInvalidSourceAddress:
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
    LogInfo("Mac Security Error 0x%02x", aCommStatusIndication->mStatus);

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
        DumpDebg("From: ", aCommStatusIndication->mSrcAddr, 2);
        if ((neighbor = Get<NeighborTable>().FindNeighbor(srcAddr)) != NULL)
        {
            uint8_t buffer[128];
            uint8_t len;
            LogWarn("Rejected frame from neighbor %x", srcAddr);
            otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_DEVICE_TABLE, neighbor->GetDeviceTableIndex(), &len, buffer);
            DumpDebg("DeviceDesc", buffer, len);
            otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_KEY_TABLE, aCommStatusIndication->mSecurity.mKeyIndex, &len,
                          buffer);
            DumpDebg("KeyDesc", buffer, len);
        }
    }
    else if (aCommStatusIndication->mSrcAddrMode == OT_MAC_ADDRESS_MODE_EXT)
    {
        DumpDebg("From: ", aCommStatusIndication->mSrcAddr, 8);
    }

    if (aCommStatusIndication->mSecurity.mSecurityLevel > 0)
    {
        LogDebg("Security Level: 0x%02x", aCommStatusIndication->mSecurity.mSecurityLevel);
        LogDebg("Key Id Mode: 0x%02x", aCommStatusIndication->mSecurity.mKeyIdMode);
        LogDebg("Key Index: 0x%02x", aCommStatusIndication->mSecurity.mKeyIndex);
        DumpDebg("Key Source: ", aCommStatusIndication->mSecurity.mKeySource, 8);
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

bool Mac::IsPromiscuous(void)
{
    uint8_t promiscuous;
    promiscuous = mLinks.IsPromiscuous();
    return promiscuous;
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

    LogDebg("Allocated MSDU Handle %x", mNextMsduHandle);
    return mNextMsduHandle;
}

Error Mac::Start()
{
    Error   error  = kErrorNone;
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

    Encoding::LittleEndian::WriteUint16(GetShortAddress(), buf);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_SHORT_ADDRESS, 0, 2, buf);

    CopyReversedExtAddr(GetExtAddress(), buf);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_IEEE_ADDRESS, 0, 8, buf);

    SetFrameCounter(Get<KeyManager>().GetCachedMacMaximumFrameCounter());

    if (mBeaconsEnabled)
    {
        BuildBeacon();
    }

    BuildSecurityTable();

exit:
    return error;
}

Error Mac::Stop()
{
    return otPlatMlmeReset(&GetInstance(), true);
}

uint32_t Mac::GetFrameCounter(void)
{
    uint8_t  leArray[4];
    uint32_t frameCounter;
    uint8_t  len;

    otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_FRAME_COUNTER, 0, &len, leArray);
    OT_ASSERT(len == 4);

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
    static const char *const kOperationStrings[] = {
        "Idle",                 // (0) kOperationIdle
        "ActiveScan",           // (1) kOperationActiveScan
        "EnergyScan",           // (2) kOperationEnergyScan
        "TransmitDataDirect",   // (3) kOperationTransmitDataDirect
        "TransmitDataIndirect", // (4) kOperationTransmitDataIndirect
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
        "TransmitDataCsl", // (5) kOperationTransmitDataCsl
#endif
    };

    static_assert(kOperationIdle == 0, "kOperationIdle value is incorrect");
    static_assert(kOperationActiveScan == 1, "kOperationActiveScan value is incorrect");
    static_assert(kOperationEnergyScan == 2, "kOperationEnergyScan value is incorrect");
    static_assert(kOperationTransmitDataDirect == 3, "kOperationTransmitDataDirect value is incorrect");
    static_assert(kOperationTransmitDataIndirect == 4, "kOperationTransmitDataIndirect value is incorrect");
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    static_assert(kOperationTransmitDataCsl == 5, "TransmitDataCsl value is incorrect");
#endif

    return kOperationStrings[aOperation];
}

Error FullAddr::GetAddress(Address &aAddress) const
{
    Error error = kErrorNone;

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
        error = kErrorInvalidArgs;
    }
    return error;
}

Error FullAddr::SetAddress(const Address &aAddress)
{
    Error error = kErrorNone;

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
        error = kErrorInvalidArgs;
        break;
    }
    return error;
}

Error FullAddr::SetAddress(ShortAddress aShortAddress)
{
    Error error = kErrorNone;

    mAddressMode = OT_MAC_ADDRESS_MODE_SHORT;
    Encoding::LittleEndian::WriteUint16(aShortAddress, mAddress);

    return error;
}

Error FullAddr::SetAddress(ExtAddress aExtAddress)
{
    Error error = kErrorNone;

    mAddressMode = OT_MAC_ADDRESS_MODE_EXT;
    aExtAddress.CopyTo(mAddress, ExtAddress::kReverseByteOrder);

    return error;
}

Error Mac::SetEnabled(bool aEnable)
{
    VerifyOrExit(mEnabled != aEnable);
    mEnabled = aEnable;

    if (mEnabled)
        Start();
    else
        otPlatMlmeReset(&GetInstance(), true);

exit:
    return kErrorNone;
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

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
void Mac::SetCslChannel(uint8_t aChannel)
{
    VerifyOrExit(GetCslChannel() != aChannel);

    mLinks.GetSubMac().SetCslChannel(aChannel);
    mLinks.GetSubMac().SetCslChannelSpecified(aChannel != 0);

    if (IsCslEnabled())
    {
        Get<Mle::Mle>().ScheduleChildUpdateRequest();
    }
exit:
    return;
}

void Mac::SetCslPeriod(uint16_t aPeriod)
{
    mLinks.GetSubMac().SetCslPeriod(aPeriod);

    Get<DataPollSender>().RecalculatePollPeriod();

    if ((GetCslPeriod() == 0) || IsCslEnabled())
    {
        IgnoreError(Get<Radio>().EnableCsl(GetCslPeriod(), Get<Mle::Mle>().GetParent().GetRloc16(),
                                           &Get<Mle::Mle>().GetParent().GetExtAddress()));
    }

    if (IsCslEnabled())
    {
        Get<Mle::Mle>().ScheduleChildUpdateRequest();
    }

    UpdateIdleMode();
}

bool Mac::IsCslEnabled(void) const
{
    return !GetRxOnWhenIdle() && IsCslCapable();
}

bool Mac::IsCslCapable(void) const
{
    return (GetCslPeriod() > 0) && Get<Mle::MleRouter>().IsChild() &&
           Get<Mle::Mle>().GetParent().IsEnhancedKeepAliveSupported();
}

#endif // OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
void Mac::ProcessCsl(const RxFrame &aFrame, const Address &aSrcAddr)
{
    const uint8_t *cur   = aFrame.GetHeaderIe(CslIe::kHeaderIeId);
    Child *        child = Get<ChildTable>().FindChild(aSrcAddr, Child::kInStateAnyExceptInvalid);
    const CslIe *  csl;

    VerifyOrExit(cur != nullptr && child != nullptr && aFrame.GetSecurityEnabled());

    csl = reinterpret_cast<const CslIe *>(cur + sizeof(HeaderIe));

    child->SetCslPeriod(csl->GetPeriod());
    // Use ceiling to ensure the the time diff will be within kUsPerTenSymbols
    child->SetCslPhase(csl->GetPhase());
    child->SetCslSynchronized(true);
    child->SetCslLastHeard(TimerMilli::GetNow());
    child->SetLastRxTimestamp(aFrame.GetTimestamp());
    LogDebg("Timestamp=%u Sequence=%u CslPeriod=%hu CslPhase=%hu TransmitPhase=%hu",
            static_cast<uint32_t>(aFrame.GetTimestamp()), aFrame.GetSequence(), csl->GetPeriod(), csl->GetPhase(),
            child->GetCslPhase());

    Get<CslTxScheduler>().Update();

exit:
    return;
}
#endif // OPENTHREAD_FTD && OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE

#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE && OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
void Mac::SetRadioFilterEnabled(bool aFilterEnabled)
{
    mLinks.GetSubMac().SetRadioFilterEnabled(aFilterEnabled);
    UpdateIdleMode();
}
#endif

} // namespace Mac
} // namespace ot

#endif // OPENTHREAD_CONFIG_USE_EXTERNAL_MAC
