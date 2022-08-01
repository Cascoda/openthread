/*
 *  Copyright (c) 2019, The OpenThread Authors.
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
 *   This file implements the MAC radio links.
 */

#include "mac/mac_links.hpp"

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator_getters.hpp"

namespace ot {
namespace Mac {

//---------------------------------------------------------------------------------------------------------------------
// TxFrames

TxFrames::TxFrames(Instance &aInstance)
    : InstanceLocator(aInstance)
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    , mTxFrame802154(nullptr)
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    , mTxFrameTrel(aInstance.Get<Trel::Link>().GetTransmitFrame())
#endif
{
}

#if OPENTHREAD_CONFIG_MULTI_RADIO

TxFrame &TxFrames::GetTxFrame(RadioType aRadioType)
{
    TxFrame *frame = nullptr;

    switch (aRadioType)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    case kRadioTypeIeee802154:
        frame = &mTxFrame802154;
        break;
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    case kRadioTypeTrel:
        frame = &mTxFrameTrel;
        break;
#endif
    }

    mSelectedRadioTypes.Add(aRadioType);

    return *frame;
}

TxFrame &TxFrames::GetTxFrame(RadioTypes aRadioTypes)
{
    // Return the TxFrame among all set of `aRadioTypes` with the smallest MTU.
    // Note that this is `TxFrame` to be sent out in parallel over multiple radio
    // radio links in `aRadioTypes, so we need to make sure that it fits in the
    // most restricted radio link (with smallest MTU).

    TxFrame *frame = nullptr;

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    if (aRadioTypes.Contains(kRadioTypeIeee802154))
    {
        frame = &mTxFrame802154;
    }
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    if (aRadioTypes.Contains(kRadioTypeTrel) && ((frame == nullptr) || (frame->GetMtu() > mTxFrameTrel.GetMtu())))
    {
        frame = &mTxFrameTrel;
    }
#endif

    mSelectedRadioTypes.Add(aRadioTypes);

    return *frame;
}

TxFrame &TxFrames::GetBroadcastTxFrame(void)
{
    RadioTypes allRadios;

    allRadios.AddAll();
    return GetTxFrame(allRadios);
}

#endif // #if OPENTHREAD_CONFIG_MULTI_RADIO

//---------------------------------------------------------------------------------------------------------------------
// Links

Links::Links(Instance &aInstance)
    : InstanceLocator(aInstance)
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    , mTrel(aInstance)
#endif
    , mTxFrames(aInstance)
    , mShortAddress(kShortAddrInvalid)
{
    SetShortAddress(mShortAddress);
}

void Links::CopyReversedExtAddr(const ExtAddress &aExtAddrIn, uint8_t *aExtAddrOut)
{
    size_t len = sizeof(aExtAddrIn);
    for (uint8_t i = 0; i < len; i++)
    {
        aExtAddrOut[i] = aExtAddrIn.m8[len - i - 1];
    }
}

void Links::SetPanId(PanId aPanId)
{
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    uint8_t panId[2];
    Encoding::LittleEndian::WriteUint16(aPanId, panId);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_PAN_ID, 0, 2, panId);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    mTrel.SetPanId(aPanId);
#endif
}

void Links::SetShortAddress(ShortAddress aShortAddress)
{
    uint8_t shortAddr[2];
    mShortAddress = aShortAddress;
    Encoding::LittleEndian::WriteUint16(mShortAddress, shortAddr);
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_SHORT_ADDRESS, 0, 2, shortAddr);
}

void Links::SetExtAddress(const ExtAddress &aExtAddress)
{
    otExtAddress address;

    CopyReversedExtAddr(aExtAddress, address.m8);

    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_IEEE_ADDRESS, 0, OT_EXT_ADDRESS_SIZE, address.m8);
    mExtAddress = aExtAddress;
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    mTrel.HandleExtAddressChange();
#endif
}

void Links::SetRxOnWhenBackoff(bool aRxOnWhenBackoff)
{
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    uint8_t setVal;
    setVal = aRxOnWhenBackoff ? 1 : 0;
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_RX_ON_WHEN_IDLE, 0, 1, &setVal);
#endif
    OT_UNUSED_VARIABLE(aRxOnWhenBackoff);
}

bool Links::IsPromiscuous(void)
{
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    uint8_t len;
    uint8_t promiscuous;

    otPlatMlmeGet(&GetInstance(), OT_PIB_MAC_PROMISCUOUS_MODE, 0, &len, &promiscuous);
    OT_ASSERT(len == 1);

    return promiscuous;
#endif
}

void Links::SetPromiscuous(bool aPromiscuous)
{
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    uint8_t promiscuous = aPromiscuous ? 1 : 0;
    otPlatMlmeSet(&GetInstance(), OT_PIB_MAC_PROMISCUOUS_MODE, 0, 1, &promiscuous);
#endif
    OT_UNUSED_VARIABLE(aPromiscuous);
}

void Links::Enable(void)
{
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    otPlatRadioEnable(&GetInstance());
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    mTrel.Enable();
#endif
}

int8_t Links::GetNoiseFloor(void)
{
    return
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        otPlatRadioGetReceiveSensitivity(&GetInstance());
#else
        kDefaultNoiseFloor;
#endif
}

#if OPENTHREAD_CONFIG_MULTI_RADIO
void Links::Send(TxFrame &aFrame, RadioTypes aRadioTypes)
{
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    if (aRadioTypes.Contains(kRadioTypeIeee802154) && mTxFrames.mTxFrame802154.IsEmpty())
    {
        mTxFrames.mTxFrame802154.CopyFrom(aFrame);
    }
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    if (aRadioTypes.Contains(kRadioTypeTrel) && mTxFrames.mTxFrameTrel.IsEmpty())
    {
        mTxFrames.mTxFrameTrel.CopyFrom(aFrame);
    }
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    if (aRadioTypes.Contains(kRadioTypeIeee802154))
    {
        SuccessOrAssert(mSubMac.Send());
    }
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    if (aRadioTypes.Contains(kRadioTypeTrel))
    {
        mTrel.Send();
    }
#endif
}

#endif // #if OPENTHREAD_CONFIG_MULTI_RADIO

#if !OPENTHREAD_CONFIG_USE_EXTERNAL_MAC
const KeyMaterial *Links::GetCurrentMacKey(const Frame &aFrame) const
{
    // Gets the security MAC key (for Key Mode 1) based on radio link type of `aFrame`.

    const KeyMaterial *key = nullptr;
#if OPENTHREAD_CONFIG_MULTI_RADIO
    RadioType radioType = aFrame.GetRadioType();
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
#if OPENTHREAD_CONFIG_MULTI_RADIO
    if (radioType == kRadioTypeIeee802154)
#endif
    {
        ExitNow(key = &Get<SubMac>().GetCurrentMacKey());
    }
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
#if OPENTHREAD_CONFIG_MULTI_RADIO
    if (radioType == kRadioTypeTrel)
#endif
    {
        ExitNow(key = &Get<KeyManager>().GetCurrentTrelMacKey());
    }
#endif

    OT_UNUSED_VARIABLE(aFrame);

exit:
    return key;
}

const KeyMaterial *Links::GetTemporaryMacKey(const Frame &aFrame, uint32_t aKeySequence) const
{
    // Gets the security MAC key (for Key Mode 1) based on radio link
    // type of `aFrame` and given Key Sequence.

    const KeyMaterial *key = nullptr;
#if OPENTHREAD_CONFIG_MULTI_RADIO
    RadioType radioType = aFrame.GetRadioType();
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
#if OPENTHREAD_CONFIG_MULTI_RADIO
    if (radioType == kRadioTypeIeee802154)
#endif
    {
        if (aKeySequence == Get<KeyManager>().GetCurrentKeySequence() - 1)
        {
            ExitNow(key = &Get<SubMac>().GetPreviousMacKey());
        }
        else if (aKeySequence == Get<KeyManager>().GetCurrentKeySequence() + 1)
        {
            ExitNow(key = &Get<SubMac>().GetNextMacKey());
        }
        else
        {
            OT_ASSERT(false);
        }
    }
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
#if OPENTHREAD_CONFIG_MULTI_RADIO
    if (radioType == kRadioTypeTrel)
#endif
    {
        ExitNow(key = &Get<KeyManager>().GetTemporaryTrelMacKey(aKeySequence));
    }
#endif

    OT_UNUSED_VARIABLE(aFrame);

exit:
    return key;
}
#endif // #if !OPENTHREAD_CONFIG_USE_EXTERNAL_MAC

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
void Links::SetMacFrameCounter(TxFrame &aFrame)
{
#if OPENTHREAD_CONFIG_MULTI_RADIO
    RadioType radioType = aFrame.GetRadioType();
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
#if OPENTHREAD_CONFIG_MULTI_RADIO
    if (radioType == kRadioTypeTrel)
#endif
    {
        aFrame.SetFrameCounter(Get<KeyManager>().GetTrelMacFrameCounter());
        Get<KeyManager>().IncrementTrelMacFrameCounter();
        ExitNow();
    }
#endif

exit:
    return;
}
#endif // #if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE

} // namespace Mac
} // namespace ot