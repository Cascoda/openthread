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

#include "mac_frame.hpp"

#include <stdio.h>

#include "common/code_utils.hpp"
#include "common/debug.hpp"

namespace ot {
namespace Mac {

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
        assert(false);
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
        assert(false);
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

#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
const TimeIe *Frame::GetTimeIe(void) const
{
    const TimeIe * timeIe                              = NULL;
    const uint8_t *cur                                 = NULL;
    uint8_t        oui[VendorIeHeader::kVendorOuiSize] = {VendorIeHeader::kVendorOuiNest & 0xff,
                                                   (VendorIeHeader::kVendorOuiNest >> 8) & 0xff,
                                                   (VendorIeHeader::kVendorOuiNest >> 16) & 0xff};

    cur = GetHeaderIe(kHeaderIeVendor);
    VerifyOrExit(cur != NULL);

    cur += sizeof(HeaderIe);

    timeIe = reinterpret_cast<const TimeIe *>(cur);
    VerifyOrExit(memcmp(oui, timeIe->GetVendorOui(), VendorIeHeader::kVendorOuiSize) == 0, timeIe = NULL);
    VerifyOrExit(timeIe->GetSubType() == VendorIeHeader::kVendorIeTime, timeIe = NULL);

exit:
    return timeIe;
}
#endif // OPENTHREAD_CONFIG_TIME_SYNC_ENABLE

void TxFrame::CopyFrom(const TxFrame &aFromFrame)
{
    memcpy(this, &aFromFrame, sizeof(*this));

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
    footerLen += Mac::Frame::kFcsSize;

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

// LCOV_EXCL_START

#if (OPENTHREAD_CONFIG_LOG_LEVEL >= OT_LOG_LEVEL_NOTE) && (OPENTHREAD_CONFIG_LOG_MAC == 1)

Frame::InfoString TxFrame::ToInfoString(void) const
{
    InfoString string;
    uint8_t    commandId, type;
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

    GetDstAddr(dst);

    string.Append(", sam:%d, dst:%s, sec:%s, ackreq:%s", mSrcAddrMode, dst.ToString().AsCString(),
                  mSecurity.mSecurityLevel ? "yes" : "no", GetAckRequest() ? "yes" : "no");

    return string;
}

Frame::InfoString RxFrame::ToInfoString(void) const
{
    InfoString string;
    uint8_t    commandId, type;
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

    GetSrcAddr(src);
    GetDstAddr(dst);

    string.Append(", src:%s, dst:%s, sec:%s", src.ToString().AsCString(), dst.ToString().AsCString(),
                  GetSecurityEnabled() ? "yes" : "no");

    return string;
}

BeaconPayload::InfoString BeaconPayload::ToInfoString(void) const
{
    NetworkName name;

    name.Set(GetNetworkName());

    return InfoString("name:%s, xpanid:%s, id:%d, ver:%d, joinable:%s, native:%s", name.GetAsCString(),
                      mExtendedPanId.ToString().AsCString(), GetProtocolId(), GetProtocolVersion(),
                      IsJoiningPermitted() ? "yes" : "no", IsNative() ? "yes" : "no");
}

#endif // #if (OPENTHREAD_CONFIG_LOG_LEVEL >= OT_LOG_LEVEL_NOTE) && (OPENTHREAD_CONFIG_LOG_MAC == 1)

// LCOV_EXCL_STOP

} // namespace Mac
} // namespace ot
