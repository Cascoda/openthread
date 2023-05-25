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
 *   This file implements IEEE 802.15.4 header generation and processing.
 */

#include "mac/mac_frame.hpp"

#include <stdio.h>

#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/log.hpp"
#include "radio/trel_link.hpp"
#if !OPENTHREAD_RADIO || OPENTHREAD_CONFIG_MAC_SOFTWARE_TX_SECURITY_ENABLE
#include "crypto/aes_ccm.hpp"
#endif
#include "assert.h"

namespace ot {
namespace Mac {

using ot::Encoding::LittleEndian::ReadUint16;
using ot::Encoding::LittleEndian::ReadUint32;
using ot::Encoding::LittleEndian::WriteUint16;
using ot::Encoding::LittleEndian::WriteUint32;

void HeaderIe::Init(uint16_t aId, uint8_t aLen)
{
    Init();
    SetId(aId);
    SetLength(aLen);
}

void TxFrame::InitMacHeader(uint16_t aFcf, uint8_t aSecurityControl)
{
    SetAckRequest((aFcf & kFcfAckRequest) != 0);

    // Destination PAN + Address
    switch (aFcf & kFcfDstAddrMask)
    {
    case kFcfDstAddrNone:
        mDst.mAddressMode = Address::kTypeNone;
        break;

    case kFcfDstAddrShort:
        mDst.mAddressMode = Address::kTypeShort;
        break;

    case kFcfDstAddrExt:
        mDst.mAddressMode = Address::kTypeExtended;
        break;

    default:
        OT_ASSERT(false);
    }

    // Source Address
    switch (aFcf & kFcfSrcAddrMask)
    {
    case kFcfSrcAddrNone:
        mSrcAddrMode = Address::kTypeNone;
        break;

    case kFcfSrcAddrShort:
        mSrcAddrMode = Address::kTypeShort;
        break;

    case kFcfSrcAddrExt:
        mSrcAddrMode = Address::kTypeExtended;
        break;

    default:
        OT_ASSERT(false);
    }

    // Security Header
    if (aFcf & kFcfSecurityEnabled)
    {
        mSecurity.mSecurityLevel = aSecurityControl & kSecLevelMask;

        switch (aSecurityControl & kKeyIdModeMask)
        {
        case kKeyIdMode0:
            mSecurity.mKeyIdMode = 0;
            break;

        case kKeyIdMode1:
            mSecurity.mKeyIdMode = 1;
            break;

        case kKeyIdMode2:
            mSecurity.mKeyIdMode = 2;
            mTxOptions |= OT_MAC_TX_OPTION_NS_NONCE;
            break;

        case kKeyIdMode3:
            mSecurity.mKeyIdMode = 3;
            break;
        }
    }
}

bool TxFrame::IsDstPanIdPresent(uint16_t aFcf) const
{
    bool present = true;

#if OPENTHREAD_CONFIG_MAC_HEADER_IE_SUPPORT
    if (IsVersion2015(aFcf))
    {
        switch (aFcf & (kFcfDstAddrMask | kFcfSrcAddrMask | kFcfPanidCompression))
        {
        case (kFcfDstAddrNone | kFcfSrcAddrNone):
        case (kFcfDstAddrExt | kFcfSrcAddrNone | kFcfPanidCompression):
        case (kFcfDstAddrShort | kFcfSrcAddrNone | kFcfPanidCompression):
        case (kFcfDstAddrNone | kFcfSrcAddrExt):
        case (kFcfDstAddrNone | kFcfSrcAddrShort):
        case (kFcfDstAddrNone | kFcfSrcAddrExt | kFcfPanidCompression):
        case (kFcfDstAddrNone | kFcfSrcAddrShort | kFcfPanidCompression):
        case (kFcfDstAddrExt | kFcfSrcAddrExt | kFcfPanidCompression):
            present = false;
            break;
        default:
            break;
        }
    }
    else
#endif
    {
        present = IsDstAddrPresent(aFcf);
    }

    return present;
}

bool RxFrame::IsDstPanIdPresent(uint16_t aFcf) const
{
    bool present = true;

#if OPENTHREAD_CONFIG_MAC_HEADER_IE_SUPPORT
    if (IsVersion2015(aFcf))
    {
        switch (aFcf & (kFcfDstAddrMask | kFcfSrcAddrMask | kFcfPanidCompression))
        {
        case (kFcfDstAddrNone | kFcfSrcAddrNone):
        case (kFcfDstAddrExt | kFcfSrcAddrNone | kFcfPanidCompression):
        case (kFcfDstAddrShort | kFcfSrcAddrNone | kFcfPanidCompression):
        case (kFcfDstAddrNone | kFcfSrcAddrExt):
        case (kFcfDstAddrNone | kFcfSrcAddrShort):
        case (kFcfDstAddrNone | kFcfSrcAddrExt | kFcfPanidCompression):
        case (kFcfDstAddrNone | kFcfSrcAddrShort | kFcfPanidCompression):
        case (kFcfDstAddrExt | kFcfSrcAddrExt | kFcfPanidCompression):
            present = false;
            break;
        default:
            break;
        }
    }
    else
#endif
    {
        present = IsDstAddrPresent(aFcf);
    }

    return present;
}

uint8_t Frame::GetKeySourceLength(uint8_t aKeyIdMode)
{
    uint8_t len = 0;

    switch (aKeyIdMode)
    {
    case kKeyIdMode0:
        len = kKeySourceSizeMode0;
        break;

    case kKeyIdMode1:
        len = kKeySourceSizeMode1;
        break;

    case kKeyIdMode2:
        len = kKeySourceSizeMode2;
        break;

    case kKeyIdMode3:
        len = kKeySourceSizeMode3;
        break;
    }

    return len;
}

uint8_t Frame::CalculateMicSize(uint8_t aSecurityControl)
{
    uint8_t micSize = 0;

    switch (aSecurityControl & kSecLevelMask)
    {
    case kSecNone:
    case kSecEnc:
        micSize = kMic0Size;
        break;

    case kSecMic32:
    case kSecEncMic32:
        micSize = kMic32Size;
        break;

    case kSecMic64:
    case kSecEncMic64:
        micSize = kMic64Size;
        break;

    case kSecMic128:
    case kSecEncMic128:
        micSize = kMic128Size;
        break;
    }

    return micSize;
}

#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
const TimeIe *Frame::GetTimeIe(void) const
{
    const TimeIe  *timeIe = nullptr;
    const uint8_t *cur    = nullptr;

    cur = GetHeaderIe(VendorIeHeader::kHeaderIeId);
    VerifyOrExit(cur != nullptr);

    cur += sizeof(HeaderIe);

    timeIe = reinterpret_cast<const TimeIe *>(cur);
    VerifyOrExit(timeIe->GetVendorOui() == TimeIe::kVendorOuiNest, timeIe = nullptr);
    VerifyOrExit(timeIe->GetSubType() == TimeIe::kVendorIeTime, timeIe = nullptr);

exit:
    return timeIe;
}
#endif // OPENTHREAD_CONFIG_TIME_SYNC_ENABLE

void TxFrame::CopyFrom(const TxFrame &aFromFrame)
{
    memcpy(this, &aFromFrame, sizeof(Frame));

    // mIeInfo may be null when TIME_SYNC is not enabled.
#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
    memcpy(mInfo.mTxInfo.mIeInfo, aFromFrame.mInfo.mTxInfo.mIeInfo, sizeof(otRadioIeInfo));
#endif
}

uint16_t TxFrame::GetMaxPayloadLength(void) const
{
    size_t maxLen = OT_RADIO_FRAME_MAX_SIZE;
    size_t footerLen, headerLen;

    // Table 95 to calculate auth tag length
    footerLen = 2 << (mSecurity.mSecurityLevel % 4);
    footerLen = footerLen == 2 ? 0 : footerLen;
    footerLen += Mac::Frame::kFcfSize;

    headerLen = Mac::Frame::kFcfSize + Mac::Frame::kDsnSize;
    if (mSrcAddrMode == OT_MAC_ADDRESS_MODE_SHORT)
    {
        headerLen += sizeof(otShortAddress);
    }
    else if (mSrcAddrMode == OT_MAC_ADDRESS_MODE_EXT)
    {
        headerLen += sizeof(otExtAddress);
    }

    if (mDst.mAddressMode == OT_MAC_ADDRESS_MODE_SHORT)
    {
        headerLen += sizeof(otShortAddress);
    }
    else if (mDst.mAddressMode == OT_MAC_ADDRESS_MODE_EXT)
    {
        headerLen += sizeof(otExtAddress);
    }

    headerLen += sizeof(otPanId); // DstPanId
    if (!mPanIdCompression)
    {
        headerLen += sizeof(otPanId); // SrcPanId
    }

    if (mSecurity.mSecurityLevel != 0)
    {
        headerLen += Mac::Frame::kSecurityControlSize + Mac::Frame::kMic32Size;

        switch (mSecurity.mKeyIdMode)
        {
        case 1:
            headerLen += Mac::Frame::kKeySourceSizeMode1 + Mac::Frame::kKeyIndexSize;
            break;

        case 2:
            headerLen += Mac::Frame::kKeySourceSizeMode2 + Mac::Frame::kKeyIndexSize;
            break;

        case 3:
            headerLen += Mac::Frame::kKeySourceSizeMode3 + Mac::Frame::kKeyIndexSize;
            break;
        }
    }

    return (maxLen - footerLen - headerLen);
}

uint8_t Frame::CalculateSecurityHeaderSize(uint8_t aSecurityControl)
{
    uint8_t size = kSecurityControlSize + kFrameCounterSize;

    VerifyOrExit((aSecurityControl & kSecLevelMask) != kSecNone, size = kInvalidSize);

    switch (aSecurityControl & kKeyIdModeMask)
    {
    case kKeyIdMode0:
        size += kKeySourceSizeMode0;
        break;

    case kKeyIdMode1:
        size += kKeySourceSizeMode1 + kKeyIndexSize;
        break;

    case kKeyIdMode2:
        size += kKeySourceSizeMode2 + kKeyIndexSize;
        break;

    case kKeyIdMode3:
        size += kKeySourceSizeMode3 + kKeyIndexSize;
        break;
    }

exit:
    return size;
}

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
void Frame::SetCslIe(uint16_t aCslPeriod, uint16_t aCslPhase)
{
    uint8_t *cur = GetHeaderIe(CslIe::kHeaderIeId);
    CslIe   *csl;

    VerifyOrExit(cur != nullptr);

    csl = reinterpret_cast<CslIe *>(cur + sizeof(HeaderIe));
    csl->SetPeriod(aCslPeriod);
    csl->SetPhase(aCslPhase);
exit:
    return;
}
#endif // OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE

#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_SUBJECT_ENABLE
void Frame::SetEnhAckProbingIe(const uint8_t *aValue, uint8_t aLen)
{
    uint8_t *cur = GetThreadIe(ThreadIe::kEnhAckProbingIe);

    OT_ASSERT(cur != nullptr);

    memcpy(cur + sizeof(HeaderIe) + sizeof(VendorIeHeader), aValue, aLen);
}
#endif // OPENTHREAD_CONFIG_MLE_LINK_METRICS_SUBJECT_ENABLE

#if OPENTHREAD_CONFIG_MULTI_RADIO
uint16_t Frame::GetMtu(void) const
{
    uint16_t mtu = 0;

    switch (GetRadioType())
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    case kRadioTypeIeee802154:
        mtu = OT_RADIO_FRAME_MAX_SIZE;
        break;
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    case kRadioTypeTrel:
        mtu = Trel::Link::kMtuSize;
        break;
#endif
    }

    return mtu;
}

uint8_t Frame::GetFcsSize(void) const
{
    uint8_t fcsSize = 0;

    switch (GetRadioType())
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    case kRadioTypeIeee802154:
        fcsSize = k154FcsSize;
        break;
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    case kRadioTypeTrel:
        fcsSize = Trel::Link::kFcsSize;
        break;
#endif
    }

    return fcsSize;
}

#elif OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
uint16_t Frame::GetMtu(void) const
{
    return Trel::Link::kMtuSize;
}

uint8_t Frame::GetFcsSize(void) const
{
    return Trel::Link::kFcsSize;
}
#endif

// Explicit instantiation
#if OPENTHREAD_CONFIG_MAC_HEADER_IE_SUPPORT
#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
template Error Frame::AppendHeaderIeAt<TimeIe>(uint8_t &aIndex);
#endif
#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
template Error Frame::AppendHeaderIeAt<CslIe>(uint8_t &aIndex);
#endif
template Error Frame::AppendHeaderIeAt<Termination2Ie>(uint8_t &aIndex);
#endif

#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2
Error TxFrame::GenerateEnhAck(const RxFrame &aFrame, bool aIsFramePending, const uint8_t *aIeData, uint8_t aIeLength)
{
    Error error = kErrorNone;

    uint16_t fcf = kFcfFrameAck | kFcfFrameVersion2015 | kFcfSrcAddrNone;
    Address  address;
    PanId    panId;
    uint8_t  footerLength;
    uint8_t  securityControlField;
    uint8_t  keyId;

    otDataRequest::mChannel = aFrame.otDataIndication::mChannel;
    memset(&mInfo.mTxInfo, 0, sizeof(mInfo.mTxInfo));

    // Set frame control field
    if (aIsFramePending)
    {
        fcf |= kFcfFramePending;
    }

    if (aFrame.GetSecurityEnabled())
    {
        fcf |= kFcfSecurityEnabled;
    }

    if (aFrame.IsPanIdCompressed())
    {
        fcf |= kFcfPanidCompression;
    }

    // Destination address mode
    if ((aFrame.GetFrameControlField() & kFcfSrcAddrMask) == kFcfSrcAddrExt)
    {
        fcf |= kFcfDstAddrExt;
    }
    else if ((aFrame.GetFrameControlField() & kFcfSrcAddrMask) == kFcfSrcAddrShort)
    {
        fcf |= kFcfDstAddrShort;
    }
    else
    {
        fcf |= kFcfDstAddrNone;
    }

    if (aIeLength > 0)
    {
        fcf |= kFcfIePresent;
    }

    WriteUint16(fcf, mPsdu);

    // Set sequence number
    mPsdu[kSequenceIndex] = aFrame.GetSequence();

    if (IsDstPanIdPresent())
    {
        // Set address field
        if (aFrame.IsSrcPanIdPresent())
        {
            SuccessOrExit(error = aFrame.GetSrcPanId(panId));
        }
        else if (aFrame.IsDstPanIdPresent())
        {
            SuccessOrExit(error = aFrame.GetDstPanId(panId));
        }
        else
        {
            ExitNow(error = kErrorParse);
        }

        SetDstPanId(panId);
    }

    if (aFrame.IsSrcAddrPresent())
    {
        SuccessOrExit(error = aFrame.GetSrcAddr(address));
        SetDstAddr(address);
    }

    // At this time the length of ACK hasn't been determined, set it to
    // `kMaxPsduSize` to call methods that check frame length
    mLength = kMaxPsduSize;

    // Set security header
    if (aFrame.GetSecurityEnabled())
    {
        SuccessOrExit(error = aFrame.GetSecurityControlField(securityControlField));
        SuccessOrExit(error = aFrame.GetKeyId(keyId));

        SetSecurityControlField(securityControlField);
        SetKeyId(keyId);
    }

    // Set header IE
    if (aIeLength > 0)
    {
        OT_ASSERT(aIeData != nullptr);
        memcpy(&mPsdu[FindHeaderIeIndex()], aIeData, aIeLength);
    }

    // Set frame length
    footerLength = GetFooterLength();
    OT_ASSERT(footerLength != kInvalidIndex);
    mLength = SkipSecurityHeaderIndex() + aIeLength + footerLength;

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2

// LCOV_EXCL_START

#if OT_SHOULD_LOG_AT(OT_LOG_LEVEL_NOTE)

Frame::InfoString TxFrame::ToInfoString(void) const
{
    InfoString string;
    uint8_t    type;
    Address    src, dst;

    string.Append("paylen:%d, type:", GetPayloadLength());

    type = GetType();

    switch (type)
    {
    case kFcfFrameData:
        string.Append("Data");
        break;

    default:
        string.Append("%d", type);
        break;
    }

    IgnoreError(GetDstAddr(dst));

    string.Append(", sam:%d, dst:%s, sec:%s, ackreq:%s", mSrcAddrMode, dst.ToString().AsCString(),
                  ToYesNo(GetSecurityEnabled()), ToYesNo(GetAckRequest()));

#if OPENTHREAD_CONFIG_MULTI_RADIO
    string.Append(", radio:%s", RadioTypeToString(GetRadioType()));
#endif

    return string;
}

Frame::InfoString RxFrame::ToInfoString(void) const
{
    InfoString string;
    uint8_t    type;
    Address    src, dst;

    string.Append("paylen:%d, type:", GetPayloadLength());

    type = GetType();

    switch (type)
    {
    case kFcfFrameData:
        string.Append("Data");
        break;

    default:
        string.Append("%d", type);
        break;
    }

    IgnoreError(GetSrcAddr(src));
    IgnoreError(GetDstAddr(dst));

    string.Append(", src:%d, dst:%s, sec:%s", src.ToString().AsCString(), dst.ToString().AsCString(),
                  ToYesNo(GetSecurityEnabled()));

#if OPENTHREAD_CONFIG_MULTI_RADIO
    string.Append(", radio:%s", RadioTypeToString(GetRadioType()));
#endif

    return string;
}

BeaconPayload::InfoString BeaconPayload::ToInfoString(void) const
{
    NetworkName name;
    InfoString  string;

    IgnoreError(name.Set(GetNetworkName()));

    string.Append("name:%s, xpanid:%s, id:%d, ver:%d, joinable:%s, native:%s", name.GetAsCString(),
                  mExtendedPanId.ToString().AsCString(), GetProtocolId(), GetProtocolVersion(),
                  ToYesNo(IsJoiningPermitted()), ToYesNo(IsNative()));
    return string;
}

#endif // #if OT_SHOULD_LOG_AT(OT_LOG_LEVEL_NOTE)

// LCOV_EXCL_STOP

} // namespace Mac
} // namespace ot
