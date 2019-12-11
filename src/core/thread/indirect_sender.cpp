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
 *   This file includes definitions for handling indirect transmission.
 */

#if OPENTHREAD_FTD

#include "indirect_sender.hpp"

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"
#include "common/message.hpp"
#include "thread/mesh_forwarder.hpp"
#include "thread/mle_tlvs.hpp"
#include "thread/topology.hpp"

namespace ot {

const Mac::Address &IndirectSender::ChildInfo::GetMacAddress(Mac::Address &aMacAddress) const
{
    if (mUseShortAddress)
    {
        aMacAddress.SetShort(static_cast<const Child *>(this)->GetRloc16());
    }
    else
    {
        aMacAddress.SetExtended(static_cast<const Child *>(this)->GetExtAddress());
    }

    return aMacAddress;
}

void IndirectSender::ChildInfo::SetIndirectMessage(Message *aMessage)
{
    // TODO: Move this back to header and remove log message
    otLogDebgMac("swap ind message %d -> %d", mIndirectMessage, aMessage);
    mIndirectMessage = aMessage;
}

IndirectSender::IndirectSender(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mEnabled(false)
    , mSourceMatchController(aInstance)
    , mDataPollHandler(aInstance)
{
}

void IndirectSender::Stop(void)
{
    VerifyOrExit(mEnabled);

    for (ChildTable::Iterator iter(GetInstance(), Child::kInStateAnyExceptInvalid); !iter.IsDone(); iter++)
    {
        iter.GetChild()->SetIndirectMessage(NULL);
        mSourceMatchController.ResetMessageCount(*iter.GetChild());
    }

    mDataPollHandler.Clear();

exit:
    mEnabled = false;
}

otError IndirectSender::AddMessageForSleepyChild(Message &aMessage, Child &aChild)
{
    otError  error = OT_ERROR_NONE;
    uint16_t childIndex;

    VerifyOrExit(!aChild.IsRxOnWhenIdle(), error = OT_ERROR_INVALID_STATE);

    childIndex = Get<ChildTable>().GetChildIndex(aChild);
    VerifyOrExit(!aMessage.GetChildMask(childIndex), error = OT_ERROR_ALREADY);

    aMessage.SetChildMask(childIndex);
    mSourceMatchController.IncrementMessageCount(aChild);

    RequestMessageUpdate(aChild);

exit:
    return error;
}

otError IndirectSender::RemoveMessageFromSleepyChild(Message &aMessage, Child &aChild)
{
    otError  error      = OT_ERROR_NONE;
    uint16_t childIndex = Get<ChildTable>().GetChildIndex(aChild);

    VerifyOrExit(aMessage.GetChildMask(childIndex), error = OT_ERROR_NOT_FOUND);

    aMessage.ClearChildMask(childIndex);
    mSourceMatchController.DecrementMessageCount(aChild);

    if (aChild.GetIndirectMessage() == &aMessage)
        aChild.SetIndirectMessage(NULL);

    aChild.SetWaitingForMessageUpdate(true);
    mDataPollHandler.RequestFrameChange(DataPollHandler::kPurgeFrame, aChild, &aMessage);

exit:
    return error;
}

void IndirectSender::ClearAllMessagesForSleepyChild(Child &aChild)
{
    Message *message;
    Message *nextMessage;

    VerifyOrExit(aChild.GetIndirectMessageCount() > 0);

    for (message = Get<MeshForwarder>().mSendQueue.GetHead(); message; message = nextMessage)
    {
        nextMessage = message->GetNext();

        message->ClearChildMask(Get<ChildTable>().GetChildIndex(aChild));

        if (!message->IsChildPending() && !message->GetDirectTransmission())
        {
            if (Get<MeshForwarder>().mSendMessage == message)
            {
                Get<MeshForwarder>().mSendMessage = NULL;
            }

            Get<MeshForwarder>().mSendQueue.Dequeue(*message);
            message->Free();
        }
    }

    aChild.SetIndirectMessage(NULL);
    mSourceMatchController.ResetMessageCount(aChild);

    mDataPollHandler.RequestChildPurge(aChild);

exit:
    return;
}

void IndirectSender::SetChildUseShortAddress(Child &aChild, bool aUseShortAddress)
{
    VerifyOrExit(aChild.IsIndirectSourceMatchShort() != aUseShortAddress);

    mSourceMatchController.SetSrcMatchAsShort(aChild, aUseShortAddress);

exit:
    return;
}

void IndirectSender::HandleChildModeChange(Child &aChild, Mle::DeviceMode aOldMode)
{
    if (!aChild.IsRxOnWhenIdle() && (aChild.IsStateValid()))
    {
        SetChildUseShortAddress(aChild, true);
    }

    // On sleepy to non-sleepy mode change, convert indirect messages in
    // the send queue destined to the child to direct.

    if (!aOldMode.IsRxOnWhenIdle() && aChild.IsRxOnWhenIdle() && (aChild.GetIndirectMessageCount() > 0))
    {
        uint16_t childIndex = Get<ChildTable>().GetChildIndex(aChild);

        for (Message *message = Get<MeshForwarder>().mSendQueue.GetHead(); message; message = message->GetNext())
        {
            if (message->GetChildMask(childIndex))
            {
                message->ClearChildMask(childIndex);
                message->SetDirectTransmission();
            }
        }

        aChild.SetIndirectMessage(NULL);
        mSourceMatchController.ResetMessageCount(aChild);

        mDataPollHandler.RequestChildPurge(aChild);
    }

    // Since the queuing delays for direct transmissions are expected to
    // be relatively small especially when compared to indirect, for a
    // non-sleepy to sleepy mode change, we allow any direct message
    // (for the child) already in the send queue to remain as is. This
    // is equivalent to dropping the already queued messages in this
    // case.
}

Message *IndirectSender::FindIndirectMessage(Child &aChild)
{
    Message *message;
    Message *next;
    uint16_t childIndex = Get<ChildTable>().GetChildIndex(aChild);

    for (message = Get<MeshForwarder>().mSendQueue.GetHead(); message; message = next)
    {
        next = message->GetNext();

        if (message->GetChildMask(childIndex))
        {
            // Skip and remove the supervision message if there are
            // other messages queued for the child.

            if ((message->GetType() == Message::kTypeSupervision) && (aChild.GetIndirectMessageCount() > 1))
            {
                RemoveMessageFromSleepyChild(*message, aChild);
                continue;
            }

            break;
        }
    }

    return message;
}

// TODO: Investigate this... This is not a purge in the same style as the others, this is seeking to purge
// Individual messages, and the logic of checking the child mask will fall short, as that is unset as the
// message is sent to the MAC.
void IndirectSender::RequestMessageUpdate(Child &aChild)
{
    Message *curMessage = aChild.GetIndirectMessage();
    Message *newMessage;

    VerifyOrExit(!aChild.IsWaitingForMessageUpdate());

    newMessage = FindIndirectMessage(aChild);

    VerifyOrExit(curMessage != newMessage);

    if (curMessage == NULL)
    {
        // Current message is NULL, but new message is not.
        // We have a new indirect message.

        UpdateIndirectMessage(aChild);
        ExitNow();
    }

    // TODO: Cannot currently replace a frame in the indirect queue with a higher priority one.
    /*
        // Current message and new message differ and are both non-NULL.
        // We need to request the frame to be replaced. The current
        // indirect message can be replaced only if it is the first
        // fragment. If a next fragment frame for message is already
        // prepared, we wait for the entire message to be delivered.

        VerifyOrExit(aChild.GetIndirectNextFragmentOffset() == 0);

        aChild.SetWaitingForMessageUpdate(true);
        mDataPollHandler.RequestFrameChange(DataPollHandler::kReplaceFrame, aChild);*/

exit:
    return;
}

void IndirectSender::HandleFrameChangeDone(Child &aChild)
{
    VerifyOrExit(aChild.IsWaitingForMessageUpdate());
    UpdateIndirectMessage(aChild);

exit:
    return;
}

void IndirectSender::UpdateIndirectMessage(Child &aChild)
{
    Message *message = FindIndirectMessage(aChild);

    aChild.SetWaitingForMessageUpdate(false);
    aChild.SetIndirectMessage(message);
    aChild.SetIndirectNextFragmentOffset(0);
    aChild.SetIndirectTxSuccess(true);

    if (message != NULL)
    {
        Mac::Address childAddress;

        mDataPollHandler.HandleNewFrame(aChild);

        aChild.GetMacAddress(childAddress);
        Get<MeshForwarder>().LogMessage(MeshForwarder::kMessagePrepareIndirect, *message, &childAddress, OT_ERROR_NONE);
    }
}

otError IndirectSender::PrepareFrameForChild(Mac::TxFrame &aFrame, FrameContext &aContext, Child &aChild)
{
    otError  error   = OT_ERROR_NONE;
    Message *message = aChild.GetIndirectMessage();
    uint16_t directTxOffset;

    VerifyOrExit(mEnabled, error = OT_ERROR_ABORT);

    if (message == NULL)
    {
        UpdateIndirectMessage(aChild);
        message = aChild.GetIndirectMessage();
    }
    //    TODO: Remove this for extern mac - move to DataPollHandler of the full mac version
    //    if (message == NULL)
    //    {
    //        PrepareEmptyFrame(aFrame, aChild, /* aAckRequest */ true);
    //        ExitNow();
    //    }
    if (message == NULL)
    {
        error = OT_ERROR_NOT_FOUND;
        ExitNow();
    }

    aContext.mMessage = message;
    switch (message->GetType())
    {
    case Message::kTypeIp6:
        // Prepare the data frame from child's indirect offset.
        directTxOffset          = message->GetOffset();
        aContext.mMessageOffset = aChild.GetIndirectNextFragmentOffset();
        message->SetOffset(aContext.mMessageOffset);
        otLogDebgMac("Ind Frag offset %d", aContext.mMessageOffset);
        aContext.mMessageNextOffset = PrepareDataFrame(aFrame, aChild, *message);
        message->SetOffset(directTxOffset);
        break;

    case Message::kTypeSupervision:
        PrepareEmptyFrame(aFrame, aChild, kSupervisionMsgAckRequest);
        aContext.mMessageNextOffset = message->GetLength();
        aContext.mMessageOffset     = 0;
        break;

    default:
        assert(false);
        break;
    }

exit:
    return error;
} // namespace ot

otError IndirectSender::RegenerateFrame(Mac::TxFrame &aFrame, FrameContext &aContext, Child &aChild)
{
    otError  error   = OT_ERROR_NONE;
    Message *message = aContext.mMessage;
    uint16_t directTxOffset;

    VerifyOrExit(mEnabled, error = OT_ERROR_ABORT);

    if (message == NULL)
    {
        error = OT_ERROR_NOT_FOUND;
        ExitNow();
    }

    otLogDebgMac("Regenerating indirect frame");

    aContext.mMessage = message;
    switch (message->GetType())
    {
    case Message::kTypeIp6:
        // Prepare the data frame from child's indirect offset.
        directTxOffset = message->GetOffset();
        message->SetOffset(aContext.mMessageOffset);
        aContext.mMessageNextOffset = RegenerateDataFrame(aFrame, aChild, *message);
        message->SetOffset(directTxOffset);
        break;

    case Message::kTypeSupervision:
        PrepareEmptyFrame(aFrame, aChild, kSupervisionMsgAckRequest);
        aContext.mMessageNextOffset = message->GetLength();
        aContext.mMessageOffset     = 0;
        break;

    default:
        assert(false);
        break;
    }

exit:
    return error;
}

uint16_t IndirectSender::PrepareDataFrame(Mac::TxFrame &aFrame, Child &aChild, Message &aMessage)
{
    uint16_t nextOffset = GenerateDataFrame(aFrame, aChild, aMessage);

    if (nextOffset >= aMessage.GetLength())
    {
        otLogDebgMac("Final message fragment queued.");
        aMessage.ClearChildMask(Get<ChildTable>().GetChildIndex(aChild));
        UpdateIndirectMessage(aChild);
        mSourceMatchController.DecrementMessageCount(aChild);
    }
    else
    {
        aChild.SetIndirectNextFragmentOffset(nextOffset);
    }

    // Set `FramePending` if there are more queued messages for the
    // child. The case where the current message itself requires
    // fragmentation is already checked and handled in
    // `PrepareDataFrame()` method.

    if (aChild.GetIndirectMessageCount())
    {
        aFrame.SetFramePending(true);
    }

    return nextOffset;
}

uint16_t IndirectSender::RegenerateDataFrame(Mac::TxFrame &aFrame, const Child &aChild, Message &aMessage)
{
    uint16_t nextOffset = GenerateDataFrame(aFrame, aChild, aMessage);

    // Set `FramePending` if there are more queued messages for the
    // child. The case where the current message itself requires
    // fragmentation is already checked and handled in
    // `PrepareDataFrame()` method.

    if (aChild.GetIndirectMessageCount())
    {
        aFrame.SetFramePending(true);
    }

    return nextOffset;
}

uint16_t IndirectSender::GenerateDataFrame(Mac::TxFrame &aFrame, const Child &aChild, Message &aMessage)
{
    Ip6::Header  ip6Header;
    Mac::Address macSource, macDest;
    uint16_t     nextOffset;

    // Determine the MAC source and destination addresses.

    aMessage.Read(0, sizeof(ip6Header), &ip6Header);

    Get<MeshForwarder>().GetMacSourceAddress(ip6Header.GetSource(), macSource);

    if (ip6Header.GetDestination().IsLinkLocal())
    {
        Get<MeshForwarder>().GetMacDestinationAddress(ip6Header.GetDestination(), macDest);
    }
    else
    {
        aChild.GetMacAddress(macDest);
    }

    nextOffset = Get<MeshForwarder>().PrepareDataFrame(aFrame, aMessage, macSource, macDest);

    return nextOffset;
}

void IndirectSender::PrepareEmptyFrame(Mac::TxFrame &aFrame, Child &aChild, bool aAckRequest)
{
    uint16_t     fcf;
    Mac::Address macSource, macDest;

    aChild.GetMacAddress(macDest);
    aChild.SetIndirectMessage(NULL);

    macSource.SetShort(Get<Mac::Mac>().GetShortAddress());

    if (macSource.IsShortAddrInvalid() || macDest.IsExtended())
    {
        macSource.SetExtended(Get<Mac::Mac>().GetExtAddress());
    }

    fcf = Mac::Frame::kFcfFrameData | Mac::Frame::kFcfFrameVersion2006 | Mac::Frame::kFcfPanidCompression |
          Mac::Frame::kFcfSecurityEnabled;

    if (aAckRequest)
    {
        fcf |= Mac::Frame::kFcfAckRequest;
    }

    fcf |= (macDest.IsShort()) ? Mac::Frame::kFcfDstAddrShort : Mac::Frame::kFcfDstAddrExt;
    fcf |= (macSource.IsShort()) ? Mac::Frame::kFcfSrcAddrShort : Mac::Frame::kFcfSrcAddrExt;

    aFrame.InitMacHeader(fcf, Mac::Frame::kKeyIdMode1 | Mac::Frame::kSecEncMic32);

    aFrame.SetDstPanId(Get<Mac::Mac>().GetPanId());
    aFrame.SetSrcPanId(Get<Mac::Mac>().GetPanId());
    aFrame.SetDstAddr(macDest);
    aFrame.SetSrcAddr(macSource);
    aFrame.SetPayloadLength(0);
    aFrame.SetFramePending(false);
}

void IndirectSender::HandleSentFrameToChild(FrameContext &aContext, otError aError, Child &aChild)
{
    Message *sentMessage = aContext.mMessage;

    VerifyOrExit(mEnabled);
    aContext.HandleMacDone();

    switch (aError)
    {
    case OT_ERROR_NONE:
        Get<Utils::ChildSupervisor>().UpdateOnSend(aChild);
        break;

    case OT_ERROR_NO_ACK:
    case OT_ERROR_CHANNEL_ACCESS_FAILURE:
    case OT_ERROR_ABORT:

        aChild.SetIndirectTxSuccess(false);

#if OPENTHREAD_CONFIG_DROP_MESSAGE_ON_FRAGMENT_TX_FAILURE
        // We set the nextOffset to end of message, since there is no need to
        // send any remaining fragments in the message to the child, if all tx
        // attempts of current frame already failed.

        if (sentMessage != NULL)
        {
            if (sentMessage == aChild.GetIndirectMessage())
            {
                aChild.SetIndirectMessage(NULL);
                aChild.SetIndirectNextFragmentOffset(0);
                if (sentMessage->GetType() == Message::kTypeIp6)
                    Get<MeshForwarder>().mIpCounters.mTxFailure++;
                ExitNow();
            }
        }
#endif
        break;

    default:
        assert(false);
        break;
    }

    if ((aChild.GetIndirectMessage() != NULL) &&
        (aChild.GetIndirectNextFragmentOffset() < aChild.GetIndirectMessage()->GetLength()))
    {
        mDataPollHandler.HandleNewFrame(aChild);
    }

    if (sentMessage != NULL && (aContext.mMessageNextOffset == sentMessage->GetLength()))
    {
        // The indirect tx of this message to the child is done.

        otError      txError = aError;
        Mac::Address macDest;

        aChild.GetLinkInfo().AddMessageTxStatus(aChild.GetIndirectTxSuccess());

        // Enable short source address matching after the first indirect
        // message transmission attempt to the child. We intentionally do
        // not check for successful tx here to address the scenario where
        // the child does receive "Child ID Response" but parent misses the
        // 15.4 ack from child. If the "Child ID Response" does not make it
        // to the child, then the child will need to send a new "Child ID
        // Request" which will cause the parent to switch to using long
        // address mode for source address matching.

        mSourceMatchController.SetSrcMatchAsShort(aChild, true);

#if !OPENTHREAD_CONFIG_DROP_MESSAGE_ON_FRAGMENT_TX_FAILURE

        // When `CONFIG_DROP_MESSAGE_ON_FRAGMENT_TX_FAILURE` is
        // disabled, all fragment frames of a larger message are
        // sent even if the transmission of an earlier fragment fail.
        // Note that `GetIndirectTxSuccess() tracks the tx success of
        // the entire message to the child, while `txError = aError`
        // represents the error status of the last fragment frame
        // transmission.

        if (!aChild.GetIndirectTxSuccess() && (txError == OT_ERROR_NONE))
        {
            txError = OT_ERROR_FAILED;
        }
#endif

        aChild.GetMacAddress(macDest);
        Get<MeshForwarder>().LogMessage(MeshForwarder::kMessageTransmit, *sentMessage, &macDest, txError);

        if (sentMessage->GetType() == Message::kTypeIp6)
        {
            if (txError)
            {
                Get<MeshForwarder>().mIpCounters.mTxSuccess++;
            }
            else
            {
                Get<MeshForwarder>().mIpCounters.mTxFailure++;
            }
        }

        if (!sentMessage->GetDirectTransmission() && !sentMessage->IsChildPending())
        {
            Get<MeshForwarder>().mSendQueue.Dequeue(*sentMessage);
            sentMessage->Free();
        }
    }

    mDataPollHandler.HandleNewFrame(aChild);

exit:
    if (mEnabled)
    {
        ClearMessagesForRemovedChildren();
    }
}

void IndirectSender::ClearMessagesForRemovedChildren(void)
{
    for (ChildTable::Iterator iter(GetInstance(), Child::kInStateAnyExceptValidOrRestoring); !iter.IsDone(); iter++)
    {
        if (iter.GetChild()->GetIndirectMessageCount() == 0)
        {
            continue;
        }

        ClearAllMessagesForSleepyChild(*iter.GetChild());
    }
}

} // namespace ot

#endif // #if OPENTHREAD_FTD
