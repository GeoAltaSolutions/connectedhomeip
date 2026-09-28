/*
 *
 *    Copyright (c) 2025 Project CHIP Authors
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

#include <app-common/zap-generated/cluster-objects.h>
#include <lib/core/CHIPPersistentStorageDelegate.h>
#include <lib/core/CHIPVendorIdentifiers.hpp>
#include <lib/core/DataModelTypes.h>
#include <lib/core/NodeId.h>

#include <optional>

namespace chip {
namespace app {

class JointFabricAdministrator
{
public:
    class Delegate
    {
    public:
        Delegate() {}
        virtual ~Delegate() {}

        virtual CHIP_ERROR GetIcacCsr(MutableByteSpan & icacCsr) { return CHIP_NO_ERROR; }

        /**
         * Called when AddICAC accepted a cross-signed ICAC from the anchor of the accessing fabric (JCM, joining
         * side): the ICAC chains to that fabric's root and certifies this node's ICAC CSR key.
         *
         * @param fabricIndex         the accessing (joint) fabric
         * @param icac                the cross-signed ICAC, Matter TLV; only valid during the call
         * @param peerAdminNodeId     the node that invoked AddICAC, the joint fabric's anchor administrator
         * @param peerAdminEndpointId the endpoint of its JointFabricAdministrator cluster, from
         *                            AnnounceJointFabricAdministrator
         */
        virtual void OnCrossSignedIcacAccepted(FabricIndex fabricIndex, const ByteSpan & icac, NodeId peerAdminNodeId,
                                               EndpointId peerAdminEndpointId)
        {}
    };

    static JointFabricAdministrator & GetInstance()
    {
        static JointFabricAdministrator sInstance;
        return sInstance;
    }

    void SetPeerJFAdminClusterEndpointId(chip::EndpointId peerJFAdminClusterEndpointId)
    {
        mPeerJFAdminClusterEndpointId = peerJFAdminClusterEndpointId;
    }

    void SetVidVerificationForFabric(chip::FabricIndex fabricIndex) { mVidVerificationFabricIndex = fabricIndex; }
    void ClearVidVerificationForFabric() { mVidVerificationFabricIndex.reset(); }

    /**
     * Clear cached VID-verification state when its fabric is removed.
     */
    void OnFabricRemoved(chip::FabricIndex removedFabricIndex)
    {
        if (mVidVerificationFabricIndex.has_value() && (mVidVerificationFabricIndex.value() == removedFabricIndex))
        {
            mVidVerificationFabricIndex.reset();
        }
    }
    bool WasVidVerificationExecutedForFabric(chip::FabricIndex fabricIndex) const
    {
        return mVidVerificationFabricIndex.has_value() && (mVidVerificationFabricIndex.value() == fabricIndex);
    }

    CHIP_ERROR SetDelegate(JointFabricAdministrator::Delegate * delegate)
    {
        VerifyOrReturnError(delegate != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
        mDelegate = delegate;

        return CHIP_NO_ERROR;
    }

    chip::EndpointId GetPeerJFAdminClusterEndpointId() const { return mPeerJFAdminClusterEndpointId; }

    JointFabricAdministrator::Delegate * GetDelegate() { return mDelegate; }

private:
    chip::EndpointId mPeerJFAdminClusterEndpointId = chip::kInvalidEndpointId;
    std::optional<chip::FabricIndex> mVidVerificationFabricIndex;
    JointFabricAdministrator::Delegate * mDelegate = nullptr;
};

} // namespace app
} // namespace chip
