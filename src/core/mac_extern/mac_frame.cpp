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

void Frame::InitMacHeader(uint16_t aFcf, uint8_t aSecurityControl)
{
    uint8_t *bytes  = GetPsdu();
    uint8_t  length = 0;

    // Frame Control Field
    Encoding::LittleEndian::WriteUint16(aFcf, bytes);
    length += kFcfSize;

    // Sequence Number
    length += kDsnSize;

    // Destination PAN + Address
    switch (aFcf & kFcfDstAddrMask)
    {
    case kFcfDstAddrNone:
        break;

    case kFcfDstAddrShort:
        length += sizeof(PanId) + sizeof(ShortAddress);
        break;

    case kFcfDstAddrExt:
        length += sizeof(PanId) + sizeof(ExtAddress);
        break;

    default:
        assert(false);
    }

    // Source PAN
    if (IsSrcPanIdPresent(aFcf))
    {
        length += sizeof(PanId);
    }

    // Source Address
    switch (aFcf & kFcfSrcAddrMask)
    {
    case kFcfSrcAddrNone:
        break;

    case kFcfSrcAddrShort:
        length += sizeof(ShortAddress);
        break;

    case kFcfSrcAddrExt:
        length += sizeof(ExtAddress);
        break;

    default:
        assert(false);
    }

    // Security Header
    if (aFcf & kFcfSecurityEnabled)
    {
        bytes[length] = aSecurityControl;

        if (aSecurityControl & kSecLevelMask)
        {
            length += kSecurityControlSize + kFrameCounterSize;
        }

        switch (aSecurityControl & kKeyIdModeMask)
        {
        case kKeyIdMode0:
            length += kKeySourceSizeMode0;
            break;

        case kKeyIdMode1:
            length += kKeySourceSizeMode1 + kKeyIndexSize;
            break;

        case kKeyIdMode2:
            length += kKeySourceSizeMode2 + kKeyIndexSize;
            break;

        case kKeyIdMode3:
            length += kKeySourceSizeMode3 + kKeyIndexSize;
            break;
        }
    }

    // Command ID
    if ((aFcf & kFcfFrameTypeMask) == kFcfFrameMacCmd)
    {
        length += kCommandIdSize;
    }

    SetPsduLength(length + GetFooterLength());
}

void Frame::SetAckRequest(bool aAckRequest)
{
    if (aAckRequest)
    {
        GetPsdu()[0] |= kFcfAckRequest;
    }
    else
    {
        GetPsdu()[0] &= ~kFcfAckRequest;
    }
}

void Frame::SetFramePending(bool aFramePending)
{
    if (aFramePending)
    {
        GetPsdu()[0] |= kFcfFramePending;
    }
    else
    {
        GetPsdu()[0] &= ~kFcfFramePending;
    }
}

otError Frame::GetDstPanId(PanId &aPanId) const
{
    otError error = OT_ERROR_NONE;
    uint8_t index = FindDstPanIdIndex();

    VerifyOrExit(index != kInvalidIndex, error = OT_ERROR_PARSE);
    aPanId = Encoding::LittleEndian::ReadUint16(GetPsdu() + index);

exit:
    return error;
}

void Frame::SetDstPanId(PanId aPanId)
{
    uint8_t index = FindDstPanIdIndex();

    assert(index != kInvalidIndex);
    Encoding::LittleEndian::WriteUint16(aPanId, GetPsdu() + index);
}

otError Frame::GetDstAddr(Address &aAddress) const
{
    otError error = OT_ERROR_NONE;
    uint8_t index = FindDstAddrIndex();

    VerifyOrExit(index != kInvalidIndex, error = OT_ERROR_PARSE);

    switch (GetFrameControlField() & kFcfDstAddrMask)
    {
    case kFcfDstAddrShort:
        aAddress.SetShort(Encoding::LittleEndian::ReadUint16(GetPsdu() + index));
        break;

    case kFcfDstAddrExt:
        aAddress.SetExtended(GetPsdu() + index, ExtAddress::kReverseByteOrder);
        break;

    default:
        aAddress.SetNone();
        break;
    }

exit:
    return error;
}

void Frame::SetDstAddr(ShortAddress aShortAddress)
{
    assert((GetFrameControlField() & kFcfDstAddrMask) == kFcfDstAddrShort);
    Encoding::LittleEndian::WriteUint16(aShortAddress, GetPsdu() + FindDstAddrIndex());
}

void Frame::SetDstAddr(const ExtAddress &aExtAddress)
{
    uint8_t index = FindDstAddrIndex();

    assert((GetFrameControlField() & kFcfDstAddrMask) == kFcfDstAddrExt);
    assert(index != kInvalidIndex);

    aExtAddress.CopyTo(GetPsdu() + index, ExtAddress::kReverseByteOrder);
}

void Frame::SetDstAddr(const Address &aAddress)
{
    switch (aAddress.GetType())
    {
    case Address::kTypeShort:
        SetDstAddr(aAddress.GetShort());
        break;

    case Address::kTypeExtended:
        SetDstAddr(aAddress.GetExtended());
        break;

    default:
        assert(false);
        break;
    }
}

otError Frame::GetSrcPanId(PanId &aPanId) const
{
    otError error = OT_ERROR_NONE;
    uint8_t index = FindSrcPanIdIndex();

    VerifyOrExit(index != kInvalidIndex, error = OT_ERROR_PARSE);
    aPanId = Encoding::LittleEndian::ReadUint16(GetPsdu() + index);

exit:
    return error;
}

otError Frame::GetSrcAddr(Address &aAddress) const
{
    otError  error = OT_ERROR_NONE;
    uint8_t  index = FindSrcAddrIndex();
    uint16_t fcf   = GetFrameControlField();

    VerifyOrExit(index != kInvalidIndex, error = OT_ERROR_PARSE);

    switch (fcf & kFcfSrcAddrMask)
    {
    case kFcfSrcAddrShort:
        aAddress.SetShort(Encoding::LittleEndian::ReadUint16(GetPsdu() + index));
        break;

    case kFcfSrcAddrExt:
        aAddress.SetExtended(GetPsdu() + index, ExtAddress::kReverseByteOrder);
        break;

    default:
        aAddress.SetNone();
        break;
    }

exit:
    return error;
}

void Frame::SetSrcAddr(ShortAddress aShortAddress)
{
    uint8_t index = FindSrcAddrIndex();

    assert((GetFrameControlField() & kFcfSrcAddrMask) == kFcfSrcAddrShort);
    assert(index != kInvalidIndex);

    Encoding::LittleEndian::WriteUint16(aShortAddress, GetPsdu() + index);
}

void Frame::SetSrcAddr(const ExtAddress &aExtAddress)
{
    uint8_t index = FindSrcAddrIndex();

    assert((GetFrameControlField() & kFcfSrcAddrMask) == kFcfSrcAddrExt);
    assert(index != kInvalidIndex);

    aExtAddress.CopyTo(GetPsdu() + index, ExtAddress::kReverseByteOrder);
}

void Frame::SetSrcAddr(const Address &aAddress)
{
    switch (aAddress.GetType())
    {
    case Address::kTypeShort:
        SetSrcAddr(aAddress.GetShort());
        break;

    case Address::kTypeExtended:
        SetSrcAddr(aAddress.GetExtended());
        break;

    default:
        assert(false);
        break;
    }
}

uint16_t Frame::GetMaxPayloadLength(void) const
{
    return GetMtu() - (GetHeaderLength() + GetFooterLength());
}

uint16_t Frame::GetPayloadLength(void) const
{
    return GetPsduLength() - (GetHeaderLength() + GetFooterLength());
}

void Frame::SetPayloadLength(uint16_t aLength)
{
    SetPsduLength(GetHeaderLength() + GetFooterLength() + aLength);
}

const uint8_t *Frame::GetPayload(void) const
{
    uint8_t        index   = FindPayloadIndex();
    const uint8_t *payload = GetPsdu() + index;

    VerifyOrExit(index != kInvalidIndex, payload = NULL);

exit:
    return payload;
}

#if OPENTHREAD_CONFIG_MAC_HEADER_IE_SUPPORT
otError Frame::AppendHeaderIe(HeaderIe *aIeList, uint8_t aIeCount)
{
    otError  error = OT_ERROR_NONE;
    uint8_t  index = FindHeaderIeIndex();
    uint8_t *cur;
    uint8_t *base;

    VerifyOrExit(index != kInvalidIndex, error = OT_ERROR_FAILED);
    cur  = GetPsdu() + index;
    base = cur;

    for (uint8_t i = 0; i < aIeCount; i++)
    {
        memcpy(cur, &aIeList[i], sizeof(HeaderIe));
        cur += sizeof(HeaderIe);
        cur += aIeList[i].GetLength();
    }

    SetPsduLength(GetPsduLength() + static_cast<uint8_t>(cur - base));

exit:
    return error;
}

const uint8_t *Frame::GetHeaderIe(uint8_t aIeId) const
{
    uint8_t        index   = FindHeaderIeIndex();
    const uint8_t *cur     = NULL;
    const uint8_t *payload = GetPayload();

    VerifyOrExit(index != kInvalidIndex);

    cur = GetPsdu() + index;

    while (cur + sizeof(HeaderIe) <= payload)
    {
        const HeaderIe *ie  = reinterpret_cast<const HeaderIe *>(cur);
        uint8_t         len = static_cast<uint8_t>(ie->GetLength());

        if (ie->GetId() == aIeId)
        {
            break;
        }

        cur += sizeof(HeaderIe);

        VerifyOrExit(cur + len <= payload, cur = NULL);

        cur += len;
    }

    if (cur == payload)
    {
        cur = NULL;
    }

exit:
    return cur;
}
#endif // OPENTHREAD_CONFIG_MAC_HEADER_IE_SUPPORT

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
    uint8_t *      psduBuffer   = mPsdu;
    otRadioIeInfo *ieInfoBuffer = mInfo.mTxInfo.mIeInfo;

    memcpy(this, &aFromFrame, sizeof(Frame));

    // Set the original buffer pointers back on the frame
    // which were overwritten by above `memcpy()`.

    mPsdu                 = psduBuffer;
    mInfo.mTxInfo.mIeInfo = ieInfoBuffer;

    memcpy(mPsdu, aFromFrame.mPsdu, aFromFrame.GetPsduLength());

    // mIeInfo may be null when TIME_SYNC is not enabled.
#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
    memcpy(mInfo.mTxInfo.mIeInfo, aFromFrame.mInfo.mTxInfo.mIeInfo, sizeof(otRadioIeInfo));
#endif
}

// LCOV_EXCL_START

#if (OPENTHREAD_CONFIG_LOG_LEVEL >= OT_LOG_LEVEL_NOTE) && (OPENTHREAD_CONFIG_LOG_MAC == 1)

Frame::InfoString Frame::ToInfoString(void) const
{
    InfoString string;
    uint8_t    commandId, type;
    Address    src, dst;

    string.Append("len:%d, seqnum:%d, type:", GetLength(), GetSequence());

    type = GetType();

    switch (type)
    {
    case kFcfFrameBeacon:
        string.Append("Beacon");
        break;

    case kFcfFrameData:
        string.Append("Data");
        break;

    case kFcfFrameAck:
        string.Append("Ack");
        break;

    case kFcfFrameMacCmd:
        if (GetCommandId(commandId) != OT_ERROR_NONE)
        {
            commandId = 0xff;
        }

        switch (commandId)
        {
        case kMacCmdDataRequest:
            string.Append("Cmd(DataReq)");
            break;

        case kMacCmdBeaconRequest:
            string.Append("Cmd(BeaconReq)");
            break;

        default:
            string.Append("Cmd(%d)", commandId);
            break;
        }

        break;

    default:
        string.Append("%d", type);
        break;
    }

    GetSrcAddr(src);
    GetDstAddr(dst);

    string.Append(", src:%s, dst:%s, sec:%s, ackreq:%s", src.ToString().AsCString(), dst.ToString().AsCString(),
                  GetSecurityEnabled() ? "yes" : "no", GetAckRequest() ? "yes" : "no");

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