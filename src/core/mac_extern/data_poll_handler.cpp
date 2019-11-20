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
 *   This file includes the implementation for handling of data polls and indirect frame transmission.
 */

#if OPENTHREAD_FTD

#include "data_poll_handler.hpp"

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"

namespace ot {

DataPollHandler::Callbacks::Callbacks(Instance &aInstance)
    : InstanceLocator(aInstance)
{
}

inline otError DataPollHandler::Callbacks::PrepareFrameForChild(Mac::TxFrame &aFrame,
                                                                FrameContext &aContext,
                                                                Child &       aChild)
{
    return Get<IndirectSender>().PrepareFrameForChild(aFrame, aContext, aChild);
}

inline void DataPollHandler::Callbacks::HandleSentFrameToChild(const Mac::TxFrame &aFrame,
                                                               const FrameContext &aContext,
                                                               otError             aError,
                                                               Child &             aChild)
{
    Get<IndirectSender>().HandleSentFrameToChild(aFrame, aContext, aError, aChild);
}

inline void DataPollHandler::Callbacks::HandleFrameChangeDone(Child &aChild)
{
    Get<IndirectSender>().HandleFrameChangeDone(aChild);
}

//---------------------------------------------------------

DataPollHandler::DataPollHandler(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mCallbacks(aInstance)
{
}

void DataPollHandler::Clear(void)
{
    for (ChildTable::Iterator iter(GetInstance(), ChildTable::kInStateAnyExceptInvalid); !iter.IsDone(); iter++)
    {
        Child &child = *iter.GetChild();
        child.SetFrameReplacePending(false);
        child.SetFramePurgePending(false);
        // TODO: Complete clear process - probably have to purge every frame
    }
}

void DataPollHandler::HandleNewFrame(Child &aChild)
{
    if (aChild.GetFrameCount() == 0)
    {
        // Request from mac
        Get<Mac::Mac>().RequestIndirectFrameTransmission();
    }
}

void DataPollHandler::RequestFrameChange(FrameChange aChange, Child &aChild)
{
    /* TODO: Implement this. For purge just purge. For Change, purge then replace. */
    if ((mIndirectTxChild == &aChild))
    {
        switch (aChange)
        {
        case kReplaceFrame:
            aChild.SetFrameReplacePending(true);
            break;

        case kPurgeFrame:
            aChild.SetFramePurgePending(true);
            break;
        }
    }
    else
    {
        mCallbacks.HandleFrameChangeDone(aChild);
    }
}

void DataPollHandler::HandleDataPoll(Mac::RxPoll &aPollInd)
{
    Mac::Address macSource;
    Child *      child;
    uint16_t     indirectMsgCount;

    VerifyOrExit(aPollInd.GetSecurityEnabled());
    VerifyOrExit(Get<Mle::MleRouter>().GetRole() != OT_DEVICE_ROLE_DETACHED);

    SuccessOrExit(aPollInd.GetSrcAddr(macSource));
    child = Get<ChildTable>().FindChild(macSource, ChildTable::kInStateValidOrRestoring);
    VerifyOrExit(child != NULL);

    child->SetLastHeard(TimerMilli::GetNow());
    child->ResetLinkFailures();
    indirectMsgCount = child->GetIndirectMessageCount();

    otLogInfoMac("Rx data poll, src:0x%04x, qed_msgs:%d, rss:%d, ack-fp:%d", child->GetRloc16(), indirectMsgCount,
                 aFrame.GetRssi(), aFrame.IsAckedWithFramePending());

    /* TODO: Maybe catch here if a poll was received with a different source address type
     * than expected.
     */

exit:
    return;
}

otError DataPollHandler::HandleFrameRequest(Mac::TxFrame &aFrame)
{
    otError error = OT_ERROR_NONE;

    for (ChildTable::Iterator iter(GetInstance(), ChildTable::kInStateAnyExceptInvalid); !iter.IsDone(); iter++)
    {
        Child &child = *iter.GetChild();

        if (child.GetFrameCount() == 0 && child.GetIndirectMessageCount())
        {
            error = mCallbacks.PrepareFrameForChild(aFrame, mFrameContext, child)
        }
    }

exit:
    return error;
}

void DataPollHandler::HandleSentFrame(const Mac::TxFrame &aFrame, otError aError)
{
    Child *child = NULL;

    // TODO: Get Child from list based on the MsduHandle

    VerifyOrExit(child != NULL);

    HandleSentFrame(aFrame, aError, *child);

exit:
    return;
}

void DataPollHandler::HandleSentFrame(const Mac::TxFrame &aFrame, otError aError, Child &aChild)
{
    aChild.DecrementFrameCount();

    if (aChild.IsFramePurgePending())
    {
        aChild.SetFramePurgePending(false);
        aChild.SetFrameReplacePending(false);
        mCallbacks.HandleFrameChangeDone(aChild);
        ExitNow();
    }

    switch (aError)
    {
    case OT_ERROR_NONE:
        aChild.SetFrameReplacePending(false);
        break;

    case OT_ERROR_NO_ACK:
        otLogInfoMac("Indirect tx to child %04x failed, attempt %d/%d", aChild.GetRloc16(),
                     aChild.GetIndirectTxAttempts(), kMaxPollTriggeredTxAttempts);

        // Fall through

    case OT_ERROR_CHANNEL_ACCESS_FAILURE:
    case OT_ERROR_ABORT:

        if (aChild.IsFrameReplacePending())
        {
            aChild.SetFrameReplacePending(false);
            mCallbacks.HandleFrameChangeDone(aChild);
            ExitNow();
        }

        break;

    default:
        assert(false);
        break;
    }

    mCallbacks.HandleSentFrameToChild(aFrame, mFrameContext, aError, aChild);

exit:
    return;
}

} // namespace ot

#endif // #if OPENTHREAD_FTD
