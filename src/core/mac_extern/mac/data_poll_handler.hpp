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
 *   This file includes definitions for handling of data polls and indirect frame transmission.
 */

#ifndef DATA_POLL_HANDLER_HPP_
#define DATA_POLL_HANDLER_HPP_

#include "openthread-core-config.h"

#include "common/code_utils.hpp"
#include "common/locator.hpp"
#include "common/timer.hpp"
#include "mac/mac.hpp"
#include "mac/mac_frame.hpp"
#include "thread/indirect_sender_frame_context.hpp"

namespace ot {

/**
 * @addtogroup core-data-poll-handler
 *
 * @brief
 *   This module includes definitions for data poll handler.
 *
 * @{
 */

class Child;
namespace Mac {
class Mac;
}

/**
 * This class implements the data poll (mac data request command) handler.
 *
 */
class DataPollHandler : public InstanceLocator
{
    friend class Mac::Mac;

public:
    enum
    {
        kMaxPollTriggeredTxAttempts = OPENTHREAD_CONFIG_MAC_MAX_TX_ATTEMPTS_INDIRECT_POLLS,
        kMaxAttachedSEDs            = OPENTHREAD_CONFIG_EXTERNAL_MAC_MAX_SEDS,
        kMaxIndirectMessages        = OPENTHREAD_CONFIG_EXTERNAL_MAC_INDIRECT_QUEUE_LEN,
    };

    /**
     * This enumeration defines frame change request types used as input to `RequestFrameChange()`.
     *
     */
    enum FrameChange
    {
        kPurgeFrame,   ///< Indicates that previous frame should be purged. Any ongoing indirect tx should be aborted.
        kReplaceFrame, ///< Indicates that previous frame needs to be replaced with a new higher priority one.
    };

    /**
     * This class defines all the child info required for handling of data polls and indirect frame transmissions.
     *
     * `Child` class publicly inherits from this class.
     *
     */
    class ChildInfo
    {
        friend class DataPollHandler;

    private:
        bool IsFrameReplacePending(void) const { return mFrameReplacePending; }
        void SetFrameReplacePending(bool aReplacePending) { mFrameReplacePending = aReplacePending; }

        uint8_t GetFrameCount(void) const { return mFrameCount; }
        void    IncrementFrameCount(void) { mFrameCount++; }
        void    DecrementFrameCount(void) { mFrameCount--; }

        bool    mFrameReplacePending : 1; ///< Indicates a pending replace request for the current indirect frame.
        uint8_t mFrameCount : 7;          ///< Count of frames that are being processed by the MAC layer.
    };

    /**
     * This class defines the callbacks used by the `DataPollHandler`.
     *
     */
    class Callbacks : public InstanceLocator
    {
        friend class DataPollHandler;

    private:
        /**
         * This type defines the frame context associated with a prepared frame.
         *
         * Data poll handler treats `FrameContext` as an opaque data type. Data poll handler provides the
         * buffer/object for the context when a new frame is prepared (from the callback `PrepareFrameForChild()`).
         * It ensures to save the context along with the prepared frame and provide the same context back in the
         * callback `HandleSentFrameToChild()` when the indirect transmission of the frame is finished.
         *
         */
        typedef IndirectSenderBase::FrameContext FrameContext;

        /**
         * This constructor initializes the data poll handler object.
         *
         * @param[in]  aInstance   A reference to the OpenThread instance.
         *
         */
        explicit Callbacks(Instance &aInstance);

        /**
         * This callback method requests a frame to be prepared for indirect transmission to a given sleepy child.
         *
         * @param[out] aFrame    A reference to a MAC frame where the new frame would be placed.
         * @param[out] aContext  A reference to a `FrameContext` where the context for the new frame would be
         * placed.
         * @param[in]  aChild    The child for which to prepare the frame.
         *
         * @retval OT_ERROR_NONE   Frame was prepared successfully
         * @retval OT_ERROR_ABORT  Indirect transmission to child should be aborted (no frame for the child).
         *
         */
        otError PrepareFrameForChild(Mac::TxFrame &aFrame, FrameContext &aContext, Child &aChild);

        /**
         * This callback method requests a frame to be regenerated for indirect transmission from a given FrameContext.
         *
         * @param[out] aFrame    A reference to a MAC frame where the new frame would be placed.
         * @param[in] aContext  A reference to a `FrameContext` that was used for the original frame.
         * @param[in]  aChild    The child for which to prepare the frame.
         * @param[in] aForceExtDst  Set to force the frame to be regenerated with an extended Destination address
         *
         * @retval OT_ERROR_NONE   Frame was prepared successfully
         * @retval OT_ERROR_ABORT  Indirect transmission to child should be aborted (no frame for the child).
         *
         */
        otError RegenerateFrame(Mac::TxFrame &aFrame, FrameContext &aContext, Child &aChild, bool aForceExtDst);

        /**
         * This callback method notifies the end of indirect frame transmission to a child.
         *
         * @param[in]  aContext   The context associated with the frame when it was prepared.
         * @param[in]  aError     OT_ERROR_NONE when the frame was transmitted successfully,
         *                        OT_ERROR_NO_ACK when the frame was transmitted but no ACK was received,
         *                        OT_ERROR_CHANNEL_ACCESS_FAILURE tx failed due to activity on the channel,
         *                        OT_ERROR_ABORT when transmission was aborted for other reasons.
         * @param[in]  aChild     The child to which the frame was transmitted.
         *
         */
        void HandleSentFrameToChild(FrameContext &aContext, otError aError, Child &aChild);

        /**
         * This callback method notifies that a requested frame change from `RequestFrameChange()` is processed.
         *
         * This callback indicates to the next layer that the indirect frame/message for the child can be safely
         * updated.
         *
         * @param[in]  aChild     The child to update.
         *
         */
        void HandleFrameChangeDone(Child &aChild);
    };

    class FrameCache
    {
        friend class DataPollHandler;

    private:
        bool    IsValid(void) { return mMsduHandle; }
        uint8_t GetMsduHandle(void) { return mMsduHandle; }
        Child & GetChild() const { return *mChild; }

        bool IsPurgePending(void) { return mPurgePending; }
        void SetPurgePending(void) { mPurgePending = true; }

        void Allocate(Child &aChild, uint8_t aMsduHandle);
        void Free();

        IndirectSenderBase::FrameContext &GetContext() { return mContext; }

        uint8_t                          mMsduHandle;
        IndirectSenderBase::FrameContext mContext;
        Child *                          mChild;
        bool                             mPurgePending : 1;
        bool                             mFramePending : 1;
        bool                             mPendingRetransmit : 1;
        bool                             mUseExtAddr : 1;
    };

    /**
     * This constructor initializes the data poll handler object.
     *
     * @param[in]  aInstance   A reference to the OpenThread instance.
     *
     */
    explicit DataPollHandler(Instance &aInstance);

    /**
     * This method clears any state/info saved per child for indirect frame transmission.
     *
     */
    void Clear(void);

    /**
     * This method informs data poll handler that there is a new frame for a given child.
     *
     * After this call, the data poll handler can use the `Callbacks::PrepareFrameForChild()` method to request the
     * frame to be prepared. A subsequent call to `Callbacks::PrepareFrameForChild()` should ensure to prepare the
     * same frame (this is used for retransmissions of frame by data poll handler). If/When the frame transmission
     * is finished, the data poll handler will invoke the `Callbacks::HandleSentFrameToChild()` to indicate the
     * status of the frame transmission.
     *
     * @param[in]  aChild     The child which has a new frame.
     *
     */
    void HandleNewFrame(Child &aChild);

    /**
     * This method requests a frame change for a given child.
     *
     * Two types of frame change requests are supported:
     *
     * 1) "Purge Frame" which indicates that the previous frame should be purged and any ongoing indirect tx
     * aborted. 2) "Replace Frame" which indicates that the previous frame needs to be replaced with a new higher
     * priority one.
     *
     * If there is no ongoing indirect frame transmission to the child, the request will be handled immediately and
     * the callback `HandleFrameChangeDone()` is called directly from this method itself. This callback notifies the
     * next layer that the indirect frame/message for the child can be safely updated.
     *
     * If there is an ongoing indirect frame transmission to this child, the request can not be handled immediately.
     * The following options can happen based on the request type:
     *
     * 1) In case of "purge" request, the ongoing indirect transmission is aborted and upon completion of the abort
     * the callback `HandleFrameChangeDone()` is invoked.
     *
     * 2) In case of "replace" request, the ongoing indirect transmission is allowed to finish (current tx attempt).
     *    2.a) If the tx attempt is successful, the `Callbacks::HandleSentFrameToChild()` in invoked which indicates
     *         the "replace" could not happen (in this case the `HandleFrameChangeDone()` is no longer called).
     *    2.b) If the ongoing tx attempt is unsuccessful, then callback `HandleFrameChangeDone()` is invoked to
     * allow the next layer to update the frame/message for the child.
     *
     * If there is a pending request, a subsequent call to this method is ignored except for the case where pending
     * request is for "replace frame" and new one is for "purge frame" where the "purge" overrides the "replace"
     * request.
     *
     * @param[in]  aChange    The frame change type.
     * @param[in]  aChild     The child to process its frame change.
     * @param[in]  aMessage   The message pointer for the frame being changed.
     *
     */
    void RequestFrameChange(FrameChange aChange, Child &aChild, Message *aMessage);

    /**
     * Purge all messages destined for a certain child, then invoke `HandleFrameChangeDone()` callback.
     * @param aChild
     */
    void RequestChildPurge(Child &aChild);

private:
    // Callbacks from MAC
    void    HandleDataPoll(Mac::RxPoll &aPollInd);
    otError HandleFrameRequest(Mac::TxFrame &aFrame);
    void    HandleSentFrame(otError aError, uint8_t aMsduHandle);

    void HandleSentFrame(otError aError, FrameCache &aFrameCache);

    FrameCache *GetFrameCache(uint8_t aMsduHandle);
    FrameCache *GetNextFrameCache(Child &aChild, FrameCache *aPrevCache);
    FrameCache *GetEmptyFrameCache(void);
    uint8_t     GetDoubleBufferCount(void);

    Callbacks  mCallbacks;
    FrameCache mFrameCache[kMaxIndirectMessages];
};

/**
 * @}
 *
 */

} // namespace ot

#endif // DATA_POLL_HANDLER_HPP_
