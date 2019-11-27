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

#include "mac/data_poll_handler.hpp"

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

inline void DataPollHandler::Callbacks::HandleSentFrameToChild(const FrameContext &aContext,
                                                               otError             aError,
                                                               Child &             aChild)
{
    Get<IndirectSender>().HandleSentFrameToChild(aContext, aError, aChild);
}

inline void DataPollHandler::Callbacks::HandleFrameChangeDone(Child &aChild)
{
    Get<IndirectSender>().HandleFrameChangeDone(aChild);
}

//---------------------------------------------------------

void DataPollHandler::FrameCache::Allocate(Child &aChild, uint8_t aMsduHandle)
{
    mChild      = &aChild;
    mMsduHandle = aMsduHandle;
    aChild.IncrementFrameCount();
}

void DataPollHandler::FrameCache::Free()
{
    if (!IsValid())
        return;
    mMsduHandle = 0;
    mChild->DecrementFrameCount();
}

//---------------------------------------------------------

DataPollHandler::DataPollHandler(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mCallbacks(aInstance)
    , mFrameCache()
{
}

void DataPollHandler::Clear(void)
{
    for (ChildTable::Iterator iter(GetInstance(), ChildTable::kInStateAnyExceptInvalid); !iter.IsDone(); iter++)
    {
        Child &child = *iter.GetChild();
        child.SetFrameReplacePending(false);
    }

    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (!fc.IsValid())
            continue;

        Get<Mac::Mac>().PurgeIndirectFrame(fc.GetMsduHandle());
        fc.Free();
    }
}

void DataPollHandler::HandleNewFrame(Child &aChild)
{
    OT_UNUSED_VARIABLE(aChild);
    // Request from mac
    Get<Mac::Mac>().RequestIndirectFrameTransmission();
}

void DataPollHandler::RequestFrameChange(FrameChange aChange, Child &aChild)
{
    FrameCache *frameCache = NULL;

    while ((frameCache = GetFrameCache(aChild)))
    {
        otError error = Get<Mac::Mac>().PurgeIndirectFrame(frameCache->GetMsduHandle());

        if (!error)
            frameCache->Free();
    }

    switch (aChange)
    {
    case kReplaceFrame:
        aChild.SetFrameReplacePending(true);
        HandleNewFrame(aChild);
        break;
    case kPurgeFrame:
        mCallbacks.HandleFrameChangeDone(aChild);
        break;
    }
}

void DataPollHandler::HandleDataPoll(Mac::RxPoll &aPollInd)
{
    Mac::Address macSource;
    Child *      child;

    VerifyOrExit(aPollInd.GetSecurityEnabled());
    VerifyOrExit(Get<Mle::MleRouter>().GetRole() != OT_DEVICE_ROLE_DETACHED);

    SuccessOrExit(aPollInd.GetSrcAddr(macSource));
    child = Get<ChildTable>().FindChild(macSource, ChildTable::kInStateValidOrRestoring);
    VerifyOrExit(child != NULL);

    child->SetLastHeard(TimerMilli::GetNow());
    child->ResetLinkFailures();

    otLogInfoMac("Rx data poll, src:0x%04x, qed_msgs:%d, lqi:%d", child->GetRloc16(), child->GetIndirectMessageCount(),
                 aPollInd.GetLqi());

    /* TODO: Maybe catch here if a poll was received with a different source address type
     * than expected.
     */

exit:
    return;
}

otError DataPollHandler::HandleFrameRequest(Mac::TxFrame &aFrame)
{
    otError error = OT_ERROR_NOT_FOUND;

    for (ChildTable::Iterator iter(GetInstance(), ChildTable::kInStateAnyExceptInvalid); !iter.IsDone(); iter++)
    {
        Child &child = *iter.GetChild();

        if (child.GetFrameCount() <= 1 && child.GetIndirectMessageCount())
        {
            FrameCache *fc = GetEmptyFrameCache();

            VerifyOrExit(fc != NULL, error = OT_ERROR_NO_BUFS);

            fc->Allocate(child, Get<Mac::Mac>().GetValidMsduHandle());
            error              = mCallbacks.PrepareFrameForChild(aFrame, fc->mContext, child);
            aFrame.mMsduHandle = fc->GetMsduHandle();
            if (error)
                fc->Free();
            else
                break;
        }
    }

exit:
    return error;
}

DataPollHandler::FrameCache *DataPollHandler::GetFrameCache(uint8_t aMsduHandle)
{
    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (fc.GetMsduHandle() == aMsduHandle)
            return &fc;
    }
    return NULL;
}

DataPollHandler::FrameCache *DataPollHandler::GetFrameCache(Child &aChild)
{
    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (!fc.IsValid())
            continue;

        if (&(fc.GetChild()) == &aChild)
            return &fc;
    }
    return NULL;
}

DataPollHandler::FrameCache *DataPollHandler::GetEmptyFrameCache()
{
    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (!fc.IsValid())
            return &fc;
    }
    return NULL;
}

void DataPollHandler::HandleSentFrame(otError aError, uint8_t aMsduHandle)
{
    FrameCache *frameCache = GetFrameCache(aMsduHandle);

    if (frameCache == NULL)
        otLogWarnMac("Got confirm for unknown handle %x", aMsduHandle);
    else
        HandleSentFrame(aError, *frameCache);

    return;
}

void DataPollHandler::HandleSentFrame(otError aError, FrameCache &aFrameCache)
{
    Child &child = aFrameCache.GetChild();

    if (child.IsFrameReplacePending())
    {
        child.SetFrameReplacePending(false);
        mCallbacks.HandleFrameChangeDone(child);
        ExitNow();
    }

    switch (aError)
    {
    case OT_ERROR_NONE:
        child.SetFrameReplacePending(false);
        child.SetLastHeard(TimerMilli::GetNow());
        child.ResetLinkFailures();
        break;

    case OT_ERROR_NO_ACK:
        otLogInfoMac("Indirect tx to child %04x failed", child.GetRloc16());

        // Fall through

    case OT_ERROR_CHANNEL_ACCESS_FAILURE:
    case OT_ERROR_ABORT:

        if (child.IsFrameReplacePending())
        {
            child.SetFrameReplacePending(false);
            mCallbacks.HandleFrameChangeDone(child);
            ExitNow();
        }

        break;

    default:
        assert(false);
        break;
    }

    mCallbacks.HandleSentFrameToChild(aFrameCache.GetContext(), aError, child);

exit:
    aFrameCache.Free();
    return;
}

} // namespace ot

#endif // #if OPENTHREAD_FTD
