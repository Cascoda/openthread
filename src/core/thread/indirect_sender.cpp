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

#include "indirect_sender.hpp"

#if OPENTHREAD_FTD

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/message.hpp"
#include "thread/mesh_forwarder.hpp"
#include "thread/mle_tlvs.hpp"
#include "thread/topology.hpp"

namespace ot {

RegisterLogModule("IndirectSender");

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

IndirectSender::IndirectSender(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mEnabled(false)
    , mSourceMatchController(aInstance)
    , mDataPollHandler(aInstance)
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    , mCslTxScheduler(aInstance)
#endif
{
}

void IndirectSender::Stop(void)
{
    VerifyOrExit(mEnabled);

    for (Child &child : Get<ChildTable>().Iterate(Child::kInStateAnyExceptInvalid))
    {
        child.SetIndirectMessage(nullptr);
        mSourceMatchController.ResetMessageCount(child);
    }

    mDataPollHandler.Clear();
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    mCslTxScheduler.Clear();
#endif

exit:
    mEnabled = false;
}

void IndirectSender::AddMessageForSleepyChild(Message &aMessage, Child &aChild)
{
    uint16_t childIndex;

    OT_ASSERT(!aChild.IsRxOnWhenIdle());

    childIndex = Get<ChildTable>().GetChildIndex(aChild);
    VerifyOrExit(!aMessage.GetChildMask(childIndex));

    aMessage.SetChildMask(childIndex);
    mSourceMatchController.IncrementMessageCount(aChild);

    if ((aMessage.GetType() != Message::kTypeSupervision) && (aChild.GetIndirectMessageCount() > 1))
    {
        Message *supervisionMessage = FindIndirectMessage(aChild, /* aSupervisionTypeOnly */ true);

        if (supervisionMessage != nullptr)
        {
            IgnoreError(RemoveMessageFromSleepyChild(*supervisionMessage, aChild));
            Get<MeshForwarder>().RemoveMessageIfNoPendingTx(*supervisionMessage);
        }
    }

    RequestMessageUpdate(aChild);

exit:
    return;
}

Error IndirectSender::RemoveMessageFromSleepyChild(Message &aMessage, Child &aChild)
{
    Error    error      = kErrorNotFound;
    uint16_t childIndex = Get<ChildTable>().GetChildIndex(aChild);

    if (aMessage.GetChildMask(childIndex))
    {
        error = kErrorNone;
        aMessage.ClearChildMask(childIndex);
        mSourceMatchController.DecrementMessageCount(aChild);

        if (aChild.GetIndirectMessage() == &aMessage)
            aChild.SetIndirectMessage(NULL);
    }

    if (mDataPollHandler.IsFrameBufferedForChild(aChild, aMessage))
    {
        error = kErrorNone;
        aChild.SetWaitingForMessageUpdate(true);
        mDataPollHandler.RequestFrameChange(DataPollHandler::kPurgeFrame, aChild, &aMessage);
    }

    return error;
}

void IndirectSender::ClearAllMessagesForSleepyChild(Child &aChild)
{
    VerifyOrExit(aChild.GetIndirectMessageCount() > 0);

    for (Message &message : Get<MeshForwarder>().mSendQueue)
    {
        message.ClearChildMask(Get<ChildTable>().GetChildIndex(aChild));

        Get<MeshForwarder>().RemoveMessageIfNoPendingTx(message);
    }

    mSourceMatchController.ResetMessageCount(aChild);

#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    mCslTxScheduler.Update();
#endif

exit:
    aChild.SetIndirectMessage(nullptr);
    mDataPollHandler.RequestChildPurge(aChild);
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

        for (Message &message : Get<MeshForwarder>().mSendQueue)
        {
            if (message.GetChildMask(childIndex))
            {
                message.ClearChildMask(childIndex);
                message.SetDirectTransmission();
            }
        }

        aChild.SetIndirectMessage(nullptr);
        mSourceMatchController.ResetMessageCount(aChild);

        mDataPollHandler.RequestChildPurge(aChild);
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
        mCslTxScheduler.Update();
#endif
    }

    // Since the queuing delays for direct transmissions are expected to
    // be relatively small especially when compared to indirect, for a
    // non-sleepy to sleepy mode change, we allow any direct message
    // (for the child) already in the send queue to remain as is. This
    // is equivalent to dropping the already queued messages in this
    // case.
}

Message *IndirectSender::FindIndirectMessage(Child &aChild, bool aSupervisionTypeOnly)
{
    Message *msg        = nullptr;
    uint16_t childIndex = Get<ChildTable>().GetChildIndex(aChild);

    for (Message &message : Get<MeshForwarder>().mSendQueue)
    {
        if (message.GetChildMask(childIndex) &&
            (!aSupervisionTypeOnly || (message.GetType() == Message::kTypeSupervision)))
        {
            msg = &message;
            break;
        }
    }

    return msg;
}

// Individual messages, and the logic of checking the child mask will fall short, as that is unset as the
// message is sent to the MAC.
void IndirectSender::RequestMessageUpdate(Child &aChild)
{
    Message *curMessage = aChild.GetIndirectMessage();
    Message *newMessage;

    VerifyOrExit(!aChild.IsWaitingForMessageUpdate());

    newMessage = FindIndirectMessage(aChild);

    VerifyOrExit(curMessage != newMessage);

    if (curMessage == nullptr)
    {
        // Current message is `nullptr`, but new message is not.
        // We have a new indirect message.

        UpdateIndirectMessage(aChild);
        ExitNow();
    }

#if !OPENTHREAD_CONFIG_USE_EXTERNAL_MAC
    // Current message and new message differ and are both
    // non-`nullptr`. We need to request the frame to be replaced.
    // The current indirect message can be replaced only if it is
    // the first fragment. If a next fragment frame for message is
    // already prepared, we wait for the entire message to be
    // delivered.

    VerifyOrExit(aChild.GetIndirectNextFragmentOffset() == 0);

    aChild.SetWaitingForMessageUpdate(true);
    mDataPollHandler.RequestFrameChange(DataPollHandler::kReplaceFrame, aChild);
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    mCslTxScheduler.Update();
#endif
#endif

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

#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
    mCslTxScheduler.Update();
#endif

    if (message != nullptr)
    {
        Mac::Address childAddress;

        mDataPollHandler.HandleNewFrame(aChild);

        aChild.GetMacAddress(childAddress);
        Get<MeshForwarder>().LogMessage(MeshForwarder::kMessagePrepareIndirect, *message, &childAddress, kErrorNone);
    }
}

Error IndirectSender::PrepareFrameForChild(Mac::TxFrame &aFrame, FrameContext &aContext, Child &aChild)
{
    Error    error   = kErrorNone;
    Message *message = aChild.GetIndirectMessage();
    uint16_t directTxOffset;

    VerifyOrExit(mEnabled, error = kErrorAbort);

    if (message == NULL)
    {
        UpdateIndirectMessage(aChild);
        message = aChild.GetIndirectMessage();
    }
    // TODO: Remove this for extern mac - move to DataPollHandler of the full mac version
    // if (message == nullptr)
    // {
    //     PrepareEmptyFrame(aFrame, aChild, /* aAckRequest */ true);
    //     aContext.mMessageNextOffset = 0;
    //     ExitNow();
    // }
    if (message == nullptr)
    {
        error = kErrorNotFound;
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
        LogDebg("Ind Frag offset %d", aContext.mMessageOffset);
        aContext.mMessageNextOffset = PrepareDataFrame(aFrame, aChild, *message);
        message->SetOffset(directTxOffset);
        break;

    case Message::kTypeSupervision:
        PrepareEmptyFrame(aFrame, aChild, kSupervisionMsgAckRequest);
        aContext.mMessageNextOffset = message->GetLength();
        aContext.mMessageOffset     = 0;
        break;

    default:
        OT_ASSERT(false);
        OT_UNREACHABLE_CODE(break);
    }

exit:
    return error;
} // namespace ot

Error IndirectSender::RegenerateFrame(Mac::TxFrame &aFrame, FrameContext &aContext, Child &aChild, bool aForceExtDst)
{
    Error    error   = kErrorNone;
    Message *message = aContext.mMessage;
    uint16_t directTxOffset;

    VerifyOrExit(mEnabled, error = kErrorAbort);

    if (message == nullptr)
    {
        error = kErrorNotFound;
        ExitNow();
    }

    LogDebg("Regenerating indirect frame");

    switch (message->GetType())
    {
    case Message::kTypeIp6:
        // Prepare the data frame from child's indirect offset.
        directTxOffset = message->GetOffset();
        message->SetOffset(aContext.mMessageOffset);
        aContext.mMessageNextOffset = RegenerateDataFrame(aFrame, aChild, *message, aForceExtDst);
        message->SetOffset(directTxOffset);
        break;

    case Message::kTypeSupervision:
        PrepareEmptyFrame(aFrame, aChild, kSupervisionMsgAckRequest);
        aContext.mMessageNextOffset = message->GetLength();
        aContext.mMessageOffset     = 0;
        break;

    default:
        OT_ASSERT(false);
        break;
    }

exit:
    return error;
}

uint16_t IndirectSender::PrepareDataFrame(Mac::TxFrame &aFrame, Child &aChild, Message &aMessage)
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

    if (nextOffset >= aMessage.GetLength())
    {
        LogDebg("Final message fragment queued.");
        aMessage.ClearChildMask(Get<ChildTable>().GetChildIndex(aChild));
        UpdateIndirectMessage(aChild);
        mSourceMatchController.DecrementMessageCount(aChild);

        // Enable short source address matching after the first indirect
        // message transmission attempt to the child. We intentionally do
        // not check for successful tx here to address the scenario where
        // the child does receive "Child ID Response" but parent misses the
        // 15.4 ack from child. If the "Child ID Response" does not make it
        // to the child, then the child will need to send a new "Child ID
        // Request" which will cause the parent to switch to using long
        // address mode for source address matching.

        mSourceMatchController.SetSrcMatchAsShort(aChild, true);
    }
    else
    {
        aChild.SetIndirectNextFragmentOffset(nextOffset);
    }

    return nextOffset;
}

uint16_t IndirectSender::RegenerateDataFrame(Mac::TxFrame &aFrame, Child &aChild, Message &aMessage, bool aForceExtDst)
{
    Ip6::Header  ip6Header;
    Mac::Address macSource, macDest;
    uint16_t     nextOffset;

    aMessage.Read(0, &ip6Header, sizeof(ip6Header));
    Get<MeshForwarder>().GetMacSourceAddress(ip6Header.GetSource(), macSource);

    if (aForceExtDst)
        macDest.SetExtended(aChild.GetExtAddress());
    else
        aChild.GetMacAddress(macDest);

    nextOffset = Get<MeshForwarder>().PrepareDataFrame(aFrame, aMessage, macSource, macDest);

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

uint16_t IndirectSender::GenerateDataFrame(Mac::TxFrame &aFrame, Child &aChild, Message &aMessage)
{
    Ip6::Header  ip6Header;
    Mac::Address macSource, macDest;
    uint16_t     nextOffset;

    aMessage.Read(0, &ip6Header, sizeof(ip6Header));

    Get<MeshForwarder>().GetMacSourceAddress(ip6Header.GetSource(), macSource);

    aChild.GetMacAddress(macDest);

    nextOffset = Get<MeshForwarder>().PrepareDataFrame(aFrame, aMessage, macSource, macDest);

    return nextOffset;
}

void IndirectSender::PrepareEmptyFrame(Mac::TxFrame &aFrame, Child &aChild, bool aAckRequest)
{
    Mac::Address macDest;
    aChild.GetMacAddress(macDest);
    aChild.SetIndirectMessage(nullptr);
    Get<MeshForwarder>().PrepareEmptyFrame(aFrame, macDest, aAckRequest);
}

void IndirectSender::HandleSentFrameToChild(FrameContext &aContext, Error aError, Child &aChild)
{
    Message *sentMessage = aContext.mMessage;
    uint16_t nextOffset  = aContext.mMessageNextOffset;

    VerifyOrExit(mEnabled);
    aContext.HandleMacDone();

#if OPENTHREAD_CONFIG_CHILD_SUPERVISION_ENABLE
    if (aError == kErrorNone)
    {
        Get<Utils::ChildSupervisor>().UpdateOnSend(aChild);
    }
#endif

    // A zero `nextOffset` indicates that the sent frame is an empty
    // frame generated by `PrepareFrameForChild()` when there was no
    // indirect message in the send queue for the child. This can happen
    // in the (not common) case where the radio platform does not
    // support the "source address match" feature and always includes
    // "frame pending" flag in acks to data poll frames. In such a case,
    // `IndirectSender` prepares and sends an empty frame to the child
    // after it sends a data poll. Here in `HandleSentFrameToChild()` we
    // exit quickly if we detect the "send done" is for the empty frame
    // to ensure we do not update any newly added indirect message after
    // preparing the empty frame.

    VerifyOrExit(nextOffset != 0);

    switch (aError)
    {
    case kErrorNone:
        break;

    case kErrorNoAck:
    case kErrorChannelAccessFailure:
    case kErrorAbort:

        aChild.SetIndirectTxSuccess(false);

#if OPENTHREAD_CONFIG_DROP_MESSAGE_ON_FRAGMENT_TX_FAILURE
        // We set the nextOffset to end of message, since there is no need to
        // send any remaining fragments in the message to the child, if all tx
        // attempts of current frame already failed.

        if (sentMessage != nullptr)
        {
            if (sentMessage == aChild.GetIndirectMessage())
            {
                aChild.SetIndirectMessage(nullptr);
                aChild.SetIndirectNextFragmentOffset(0);
                if (sentMessage->GetType() == Message::kTypeIp6)
                    Get<MeshForwarder>().mIpCounters.mTxFailure++;
                ExitNow();
            }
        }
#endif
        break;

    default:
        OT_ASSERT(false);
        OT_UNREACHABLE_CODE(break);
    }

    if ((aChild.GetIndirectMessage() != nullptr &&
         (aChild.GetIndirectNextFragmentOffset() < aChild.GetIndirectMessage()->GetLength())))
    {
        mDataPollHandler.HandleNewFrame(aChild);
#if OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE
        mCslTxScheduler.Update();
#endif
    }

    if (sentMessage != nullptr && (aContext.mMessageNextOffset == sentMessage->GetLength()))
    {
        // The indirect tx of this message to the child is done.

        Error        txError = aError;
        Mac::Address macDest;

        aChild.GetLinkInfo().AddMessageTxStatus(aChild.GetIndirectTxSuccess());

#if !OPENTHREAD_CONFIG_DROP_MESSAGE_ON_FRAGMENT_TX_FAILURE

        // When `CONFIG_DROP_MESSAGE_ON_FRAGMENT_TX_FAILURE` is
        // disabled, all fragment frames of a larger message are
        // sent even if the transmission of an earlier fragment fail.
        // Note that `GetIndirectTxSuccess() tracks the tx success of
        // the entire message to the child, while `txError = aError`
        // represents the error status of the last fragment frame
        // transmission.

        if (!aChild.GetIndirectTxSuccess() && (txError == kErrorNone))
        {
            txError = kErrorFailed;
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

        Get<MeshForwarder>().RemoveMessageIfNoPendingTx(*sentMessage);
    }

    if (aChild.GetIndirectMessageCount())
    {
        mDataPollHandler.HandleNewFrame(aChild);
    }

exit:
    if (mEnabled)
    {
        ClearMessagesForRemovedChildren();
    }
}

void IndirectSender::ClearMessagesForRemovedChildren(void)
{
    for (Child &child : Get<ChildTable>().Iterate(Child::kInStateAnyExceptValidOrRestoring))
    {
        if (child.GetIndirectMessageCount() == 0)
        {
            continue;
        }

        ClearAllMessagesForSleepyChild(child);
    }
}

} // namespace ot

#endif // #if OPENTHREAD_FTD
