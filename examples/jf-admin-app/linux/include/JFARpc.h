/*
 *
 *    Copyright (c) 2025 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#pragma once

#include <lib/core/CHIPError.h>
#include <lib/core/CHIPVendorIdentifiers.hpp>
#include <lib/core/DataModelTypes.h>
#include <lib/core/NodeId.h>
#include <lib/support/Span.h>

namespace chip {

/** A joint fabric JFA joined (JCM, joining side), as JFC needs it to act on that fabric. */
struct JoinedFabricInfo
{
    FabricIndex fabricIndex = kUndefinedFabricIndex;
    FabricId fabricId       = kUndefinedFabricId;
    VendorId vendorId       = VendorId::NotSpecified;
    ByteSpan crossSignedIcac; // Matter TLV ICAC for JFC's anchor ICA key, signed by the joined fabric's root
    ByteSpan ipkEpochKey;     // the joined fabric's IPK epoch key 0
    uint32_t adminCat         = 0;
    NodeId anchorNodeId       = kUndefinedNodeId;
    EndpointId anchorEndpoint = kInvalidEndpointId;
};

class JFARpc
{
public:
    virtual ~JFARpc() {}
    virtual CHIP_ERROR GetICACCSRForJF(MutableByteSpan & icacCSR) = 0;
    /** JCM, anchor side: has JFC cross-sign the peer administrator's ICAC CSR with the anchor root. */
    virtual CHIP_ERROR GetCrossSignedICACForJF(const ByteSpan & icacCSR, FabricId anchorFabricId, MutableByteSpan & icac) = 0;
    /** JCM, joining side: tells JFC the joint fabric JFA joined. Does not wait for JFC. */
    virtual CHIP_ERROR NotifyJointFabricJoined(const JoinedFabricInfo & joined) = 0;
    virtual void CloseStreams()                                                = 0;
};

} // namespace chip
