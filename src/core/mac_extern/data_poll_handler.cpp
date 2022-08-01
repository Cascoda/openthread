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

#include "mac/data_poll_handler.hpp"

#if OPENTHREAD_FTD

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/log.hpp"
#include "thread/src_match_controller.hpp"

namespace ot {

RegisterLogModule("DataPollHandlr");

DataPollHandler::Callbacks::Callbacks(Instance &aInstance)
    : InstanceLocator(aInstance)
{
}

inline Error DataPollHandler::Callbacks::PrepareFrameForChild(Mac::TxFrame &aFrame,
                                                              FrameContext &aContext,
                                                              Child        &aChild)
{
    return Get<IndirectSender>().PrepareFrameForChild(aFrame, aContext, aChild);
}

inline Error DataPollHandler::Callbacks::RegenerateFrame(Mac::TxFrame &aFrame,
                                                         FrameContext &aContext,
                                                         Child        &aChild,
                                                         bool          aForceExtDst)
{
    return Get<IndirectSender>().RegenerateFrame(aFrame, aContext, aChild, aForceExtDst);
}

inline void DataPollHandler::Callbacks::HandleSentFrameToChild(FrameContext &aContext, Error aError, Child &aChild)
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
    mChild                  = &aChild;
    mMsduHandle             = aMsduHandle;
    mPurgePending           = false;
    mFramePending           = false;
    mPendingRetransmitPurge = false;
    mPendingRetransmit      = false;
    mUseExtAddr             = false;
    aChild.IncrementFrameCount();
    LogDebg("Allocated FrameCache %x", mMsduHandle);
}

void DataPollHandler::FrameCache::Free()
{
    if (!IsValid())
        return;
    LogDebg("Freeing FrameCache %x", mMsduHandle);
    mContext.HandleMacDone();
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
    for (Child &child : Get<ChildTable>().Iterate(Child::kInStateAnyExceptInvalid))
    {
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
    // Check if there is already a frame in the MAC with FP=false that needs updating
    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (!fc.IsValid())
            continue;

        if (&(fc.GetChild()) != &aChild)
            continue;

        if (fc.mFramePending)
            continue;

        LogDebg("Setting retransmit, handle %x, fp %d", fc.GetMsduHandle(), fc.mFramePending);
        fc.mFramePending           = true;
        fc.mPendingRetransmit      = true;
        fc.mPendingRetransmitPurge = true;
    }

    // Request from mac
    Get<Mac::Mac>().RequestIndirectFrameTransmission();
}

void DataPollHandler::RequestChildPurge(Child &aChild)
{
    FrameCache *frameCache = nullptr;

    while ((frameCache = GetNextFrameCache(aChild, frameCache)))
    {
        Error error = Get<Mac::Mac>().PurgeIndirectFrame(frameCache->GetMsduHandle());

        if (!error)
            frameCache->Free();
        else
            frameCache->SetPurgePending();
    }

    mCallbacks.HandleFrameChangeDone(aChild);
}

void DataPollHandler::RequestFrameChange(FrameChange aChange, Child &aChild, Message *aMessage)
{
    FrameCache *frameCache = nullptr;

    while ((frameCache = GetNextFrameCache(aChild, frameCache)))
    {
        Error error = kErrorNone;

        if (!frameCache->GetContext().IsForMessage(aMessage))
            continue;

        error = Get<Mac::Mac>().PurgeIndirectFrame(frameCache->GetMsduHandle());

        if (!error)
        {
            frameCache->Free();
        }
        else
        {
            // The higher layer no longer expects the message to exist, and we aren't going to regen, so remove it.
            frameCache->GetContext().HandleMacDone();
            frameCache->SetPurgePending();
        }
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

bool DataPollHandler::IsFrameBufferedForChild(Child &aChild, Message &aMessage)
{
    FrameCache *frameCache = nullptr;

    while ((frameCache = GetNextFrameCache(aChild, frameCache)))
    {
        if (frameCache->GetContext().IsForMessage(&aMessage))
            return true;
    }

    return false;
}

void DataPollHandler::HandleDataPoll(Mac::RxPoll &aPollInd)
{
    Mac::Address macSource;
    Child       *child;

    VerifyOrExit(aPollInd.GetSecurityEnabled());
    VerifyOrExit(!Get<Mle::MleRouter>().IsDetached());

    SuccessOrExit(aPollInd.GetSrcAddr(macSource));
    child = Get<ChildTable>().FindChild(macSource, Child::kInStateValidOrRestoring);
    VerifyOrExit(child != nullptr);

    child->SetLastHeard(TimerMilli::GetNow());
    child->ResetLinkFailures();
#if OPENTHREAD_CONFIG_MULTI_RADIO
    child->SetLastPollRadioType(aFrame.GetRadioType());
#endif

    LogInfo("Rx data poll, src:0x%04x, qed_msgs:%d, in_q:%d, lqi:%d", child->GetRloc16(),
            child->GetIndirectMessageCount(), child->GetFrameCount(), aPollInd.GetLqi());

    if (child->GetIndirectMessageCount())
    {
        FrameCache *frameCache = nullptr;
        LogWarn("Data poll did not trigger queued message for child %04x!", child->GetRloc16());

        if (aPollInd.mSrc.mAddressMode == OT_MAC_ADDRESS_MODE_SHORT)
        {
            // Check for indirect queued frames queued with extended address
            while ((frameCache = GetNextFrameCache(*child, frameCache)))
            {
                Error error = kErrorNone;

                if (!frameCache->mUseExtAddr)
                    continue;

                error = Get<Mac::Mac>().PurgeIndirectFrame(frameCache->GetMsduHandle());
                if (!error)
                    HandleSentFrame(kErrorAbort, *frameCache);
            }
        }
        HandleNewFrame(*child);
    }
    else if (child->GetFrameCount())
    {
        LogWarn("Data poll did not trigger queued message for child %04x!", child->GetRloc16());
        LogDebg("Dumping framecache...");
        for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
        {
            FrameCache &frameCache = mFrameCache[i];

            if (!frameCache.IsValid())
                continue;

            LogDebg("Child 0x%04x, MH %02x, PP %d, FP %d, PRP %d, PR %d, UEA %d", frameCache.GetChild().GetRloc16(),
                    frameCache.GetMsduHandle(), frameCache.mPurgePending, frameCache.mFramePending,
                    frameCache.mPendingRetransmitPurge, frameCache.mPendingRetransmit, frameCache.mUseExtAddr);
        }
    }

exit:
    return;
}

Mac::TxFrame *DataPollHandler::HandleFrameRequest(Mac::TxFrames &aTxFrames)
{
    Mac::TxFrame *frame        = nullptr;
    Child        *pendingChild = nullptr;
    uint8_t       maxBufferCount;
    Error         error = kErrorNotFound;

#if OPENTHREAD_CONFIG_MULTI_RADIO
    VerifyOrExit(mIndirectTxChild != nullptr);
    frame = aTxFrames.GetTxFrame(mIndirectTxChild->GetLastPollRadioType());
#else
    frame = aTxFrames.GetTxFrame();
#endif

    // First check if we need any frames regenerating
    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];

        if (!fc.IsValid())
            continue;

        if (!fc.mPendingRetransmit)
            continue;

        if (fc.mPendingRetransmitPurge)
        {
            Error purgeErr = Get<Mac::Mac>().PurgeIndirectFrame(fc.GetMsduHandle());
            if (!(purgeErr == kErrorNone || purgeErr == kErrorAlready))
                continue;
        }

        error              = mCallbacks.RegenerateFrame(*frame, fc.mContext, fc.GetChild(), fc.mUseExtAddr);
        frame->mMsduHandle = fc.GetMsduHandle();
        fc.mFramePending   = frame->GetFramePending();
        pendingChild       = fc.mFramePending ? &fc.GetChild() : nullptr;
        OT_ASSERT(error == kErrorNone);
        fc.mPendingRetransmit = false;
        Get<Mac::Mac>().RequestIndirectFrameTransmission();
        ExitNow();
    }

    // Calculate whether or not we strictly have room for more double-buffer indirects
    if (GetDoubleBufferCount() > (kMaxIndirectMessages - kMaxAttachedSEDs))
        maxBufferCount = 1;
    else
        maxBufferCount = 2;

    // Now check for new frames that need sending
    for (Child &child : Get<ChildTable>().Iterate(Child::kInStateAnyExceptInvalid))
    {
        // TODO: Add fairness to child buffering (only relevant when more SEDs than SED slots).
        if (child.GetFrameCount() < maxBufferCount && child.GetIndirectMessageCount())
        {
            FrameCache *fc = GetEmptyFrameCache();

            VerifyOrExit(fc != nullptr, error = kErrorNoBufs);

            fc->Allocate(child, Get<Mac::Mac>().GetValidMsduHandle());
            error              = mCallbacks.PrepareFrameForChild(*frame, fc->mContext, child);
            frame->mMsduHandle = fc->GetMsduHandle();
            fc->mFramePending  = frame->GetFramePending();
            fc->mUseExtAddr    = frame->mDst.mAddressMode == OT_MAC_ADDRESS_MODE_EXT;
            pendingChild       = fc->mFramePending ? &fc->GetChild() : nullptr;
            fc->mContext.HandleSentToMac();
            if (error)
            {
                LogDebg("HandleFrameRequest for child 0x%04x failed with error %s", child.GetRloc16(),
                        otThreadErrorToString(error));

                pendingChild = nullptr;
                error        = kErrorNotFound;
                fc->Free();
            }
            else
            {
                ExitNow();
            }
        }
    }

exit:
    if (!error && pendingChild)
    {
        HandleNewFrame(*pendingChild);
    }
    if (error)
    {
        frame = nullptr;
    }
    return frame;
}

DataPollHandler::FrameCache *DataPollHandler::GetFrameCache(uint8_t aMsduHandle)
{
    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (fc.GetMsduHandle() == aMsduHandle)
            return &fc;
    }
    return nullptr;
}

DataPollHandler::FrameCache *DataPollHandler::GetNextFrameCache(Child &aChild, FrameCache *aPrevCache)
{
    size_t i = 0;

    // Start looking after the previous cache.
    if (aPrevCache)
        i = (aPrevCache - mFrameCache) + 1;

    for (; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (!fc.IsValid())
            continue;

        if (&(fc.GetChild()) == &aChild)
            return &fc;
    }
    return nullptr;
}

uint8_t DataPollHandler::GetDoubleBufferCount()
{
    uint8_t count = 0;

    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (!fc.IsValid())
            continue;

        for (size_t j = i + 1; j < OT_ARRAY_LENGTH(mFrameCache); j++)
        {
            FrameCache &fc2 = mFrameCache[j];
            if (!fc2.IsValid())
                continue;

            if (&fc.GetChild() == &fc2.GetChild())
                count++;
        }
    }
    return count;
}

DataPollHandler::FrameCache *DataPollHandler::GetEmptyFrameCache()
{
    for (size_t i = 0; i < OT_ARRAY_LENGTH(mFrameCache); i++)
    {
        FrameCache &fc = mFrameCache[i];
        if (!fc.IsValid())
            return &fc;
    }
    LogWarn("Failed to GetEmptyFrameCache");
    return nullptr;
}

void DataPollHandler::HandleSentFrame(otError aError, uint8_t aMsduHandle)
{
    FrameCache *frameCache = GetFrameCache(aMsduHandle);

    if (frameCache == nullptr)
        LogWarn("Got confirm for unknown handle %x", aMsduHandle);
    else
        HandleSentFrame(aError, *frameCache);

    return;
}

void DataPollHandler::HandleSentFrame(Error aError, FrameCache &aFrameCache)
{
    Child &child = aFrameCache.GetChild();

    if (child.IsFrameReplacePending() || aFrameCache.IsPurgePending())
    {
        child.SetFrameReplacePending(false);
        mCallbacks.HandleFrameChangeDone(child);
        ExitNow();
    }

    if (aError == kErrorFailed)
    {
        // Some kind of system error, try again.
        aFrameCache.mPendingRetransmit = true;
        Get<Mac::Mac>().RequestIndirectFrameTransmission();
        return; // Return now so we don't free.
    }

    switch (aError)
    {
    case kErrorNone:
        child.SetFrameReplacePending(false);
        child.SetLastHeard(TimerMilli::GetNow());
        child.ResetLinkFailures();
        break;

    case kErrorNoAck:
        LogInfo("Indirect tx to child %04x failed", child.GetRloc16());

        // Fall through

    case kErrorChannelAccessFailure:
    case kErrorAbort:

        if (child.IsFrameReplacePending())
        {
            child.SetFrameReplacePending(false);
            mCallbacks.HandleFrameChangeDone(child);
            ExitNow();
        }

        break;

    default:
        OT_ASSERT(false);
        break;
    }

    mCallbacks.HandleSentFrameToChild(aFrameCache.GetContext(), aError, child);

exit:
    aFrameCache.Free();
    return;
}

} // namespace ot

#endif // #if OPENTHREAD_FTD
