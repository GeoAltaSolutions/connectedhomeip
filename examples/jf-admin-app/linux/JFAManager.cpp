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

#include "JFAManager.h"

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/ConcreteAttributePath.h>
#include <app/server/Server.h>

#if CHIP_DEVICE_CONFIG_ENABLE_BOTH_COMMISSIONER_AND_COMMISSIONEE
#include <CommissionerMain.h>
#endif // CHIP_DEVICE_CONFIG_ENABLE_BOTH_COMMISSIONER_AND_COMMISSIONEE

#include <controller/CHIPCluster.h>
#include <credentials/GroupDataProvider.h>
#include <lib/core/CASEAuthTag.h>
#include <lib/support/logging/CHIPLogging.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::Controller;
using namespace chip::Crypto;
using namespace chip::app::Clusters::JointFabricAdministrator;

constexpr uint8_t kJFAvailableShift = 0;
constexpr uint8_t kJFAdminShift     = 1;
constexpr uint8_t kJFAnchorShift    = 2;
constexpr uint8_t kJFDatastoreShift = 3;

constexpr chip::EndpointId kJointFabricAdminEndpointId = 1;

JFAManager JFAManager::sJFA;

CHIP_ERROR JFAManager::Init(Server & server)
{
    mServer             = &server;
    mCASESessionManager = server.GetCASESessionManager();

    return CHIP_NO_ERROR;
}

CHIP_ERROR JFAManager::GetJointFabricMode(uint8_t & jointFabricMode)
{
    jointFabricMode = ((IsDeviceCommissioned() ? 0 : 1) << kJFAvailableShift) |
        (IsDeviceCommissioned() ? (IsDeviceJFAdmin() ? (1 << kJFAdminShift) : 0) : 0) |
        (IsDeviceCommissioned() ? (IsDeviceJFAnchor() ? (1 << kJFAnchorShift) : 0) : 0) |
        (IsDeviceCommissioned() ? (1 << kJFDatastoreShift) : 0);
    return CHIP_NO_ERROR;
}

CHIP_ERROR JFAManager::FinalizeCommissioning(NodeId nodeId, bool isJCM, P256PublicKey & trustedIcacPublicKeyB, uint16_t endpointId)
{
    if (jfFabricIndex == kUndefinedFabricId)
    {
        return CHIP_ERROR_INCORRECT_STATE;
    }

    ChipLogProgress(JointFabric, "FinalizeCommissioning for NodeID: 0x" ChipLogFormatX64 ", isJCM = %d, peerEndpointId = %d",
                    ChipLogValueX64(nodeId), isJCM, endpointId);

    peerAdminJFAdminClusterEndpointId = endpointId;
    peerAdminICACPubKey               = trustedIcacPublicKeyB;
    ScopedNodeId scopedNodeId         = ScopedNodeId(nodeId, jfFabricIndex);
    ConnectToNode(scopedNodeId, isJCM ? kJCMCommissioning : kStandardCommissioningComplete);

    return CHIP_NO_ERROR;
}

void JFAManager::SetJFARpc(JFARpc & aJFARpc)
{
    mJFARpc = &aJFARpc;
}

JFARpc * JFAManager::GetJFARpc()
{
    return mJFARpc;
}

void JFAManager::HandleCommissioningCompleteEvent(FabricIndex completedFabricIndex)
{
    // Joining side of JCM: the joint fabric's commissioning completed, so it is ours to keep. Fetch its IPK from the
    // anchor's datastore, then hand the fabric to JFC.
    if (mPendingJoin.active && mPendingJoin.fabricIndex == completedFabricIndex)
    {
        ChipLogProgress(JointFabric, "Joined joint fabric index %u, reading its IPK from the anchor's datastore",
                        static_cast<unsigned>(completedFabricIndex));
        ConnectToNode(ScopedNodeId(mPendingJoin.peerNodeId, completedFabricIndex), kReadJointFabricIpk);
        return;
    }

    for (const auto & fb : mServer->GetFabricTable())
    {
        FabricIndex fabricIndex = fb.GetFabricIndex();
        CATValues cats;

        if ((jfFabricIndex == kUndefinedFabricIndex) && mServer->GetFabricTable().FetchCATs(fabricIndex, cats) == CHIP_NO_ERROR)
        {
            /* When JFA is commissioned, it has to be issued a NOC with Anchor CAT and Administrator CAT */
            if (cats.ContainsIdentifier(kAdminCATIdentifier) && cats.ContainsIdentifier(kAnchorCATIdentifier))
            {
                (void) app::Clusters::JointFabricAdministrator::Attributes::AdministratorFabricIndex::Set(
                    kJointFabricAdminEndpointId, fabricIndex);

                jfFabricIndex = fabricIndex;

                // Record the joint fabric index so the datastore can be purged if this fabric is ever removed.
                Server::GetInstance().GetJointFabricDatastore().SetAnchorFabricIndex(fabricIndex);

                // Set AnchorRootCA
                uint8_t mAnchorRootCABuffer[Credentials::kMaxDERCertLength];
                MutableByteSpan rootCertSpan(mAnchorRootCABuffer);
                if (mServer->GetFabricTable().FetchRootCert(fabricIndex, rootCertSpan) == CHIP_NO_ERROR)
                {
                    if (Server::GetInstance().GetJointFabricDatastore().SetAnchorRootCA(rootCertSpan) == CHIP_NO_ERROR)
                    {
                        ChipLogProgress(JointFabric, "Set AnchorRootCA (%u bytes)", static_cast<unsigned>(rootCertSpan.size()));
                    }
                    else
                    {
                        ChipLogError(JointFabric, "Failed to set AnchorRootCA");
                    }
                }

                // obtain nodeid and use it to set anchornodeid
                NodeId nodeId = fb.GetNodeId();
                if (nodeId != kUndefinedNodeId)
                {
                    if (Server::GetInstance().GetJointFabricDatastore().SetAnchorNodeId(nodeId) == CHIP_NO_ERROR)
                    {
                        ChipLogProgress(JointFabric, "Set AnchorNodeId to 0x" ChipLogFormatX64, ChipLogValueX64(nodeId));
                    }
                    else
                    {
                        ChipLogError(JointFabric, "Failed to set AnchorNodeId to 0x" ChipLogFormatX64, ChipLogValueX64(nodeId));
                    }
                }

                VendorId vendorId = fb.GetVendorId();
                if (vendorId != VendorId::NotSpecified)
                {
                    if (Server::GetInstance().GetJointFabricDatastore().SetAnchorVendorId(vendorId) == CHIP_NO_ERROR)
                    {
                        ChipLogProgress(JointFabric, "Set AnchorVendorId to %d", vendorId);
                    }
                    else
                    {
                        ChipLogError(JointFabric, "Failed to set AnchorVendorId to %d", vendorId);
                    }
                }

                if (vendorId != VendorId::NotSpecified && nodeId != kUndefinedNodeId)
                {
                    char friendlyNameBuffer[32];
                    int written = snprintf(friendlyNameBuffer, sizeof(friendlyNameBuffer), "jfa-0x%04X-0x" ChipLogFormatX64,
                                           to_underlying(vendorId), ChipLogValueX64(nodeId));
                    CharSpan friendlyName = CharSpan(friendlyNameBuffer, static_cast<size_t>(written));

                    if (Server::GetInstance().GetJointFabricDatastore().SetFriendlyName(friendlyName) == CHIP_NO_ERROR)
                    {
                        ChipLogProgress(JointFabric, "Set FriendlyName to %.*s", static_cast<int>(friendlyName.size()),
                                        friendlyName.data());
                    }
                    else
                    {
                        ChipLogError(JointFabric, "Failed to set FriendlyName to %.*s", static_cast<int>(friendlyName.size()),
                                     friendlyName.data());
                    }
                }

                Server::GetInstance().GetJointFabricDatastore().SetStatus(
                    Clusters::JointFabricDatastore::DatastoreStateEnum::kPending,
                    static_cast<uint32_t>(System::SystemClock().GetMonotonicTimestamp().count()), 0);

                Clusters::JointFabricDatastore::Structs::DatastoreGroupKeySetStruct::Type defaultGroupKeySetEntry{ 0 };
                LogErrorOnFailure(Server::GetInstance().GetJointFabricDatastore().AddGroupKeySetEntry(defaultGroupKeySetEntry));
                LogErrorOnFailure(Server::GetInstance().GetJointFabricDatastore().ForceAddNodeKeySetEntry(0, nodeId));

                // Add default group entry for the JFA itself
                // Uses internal method that bypasses CAT restrictions since JFA setup needs both Admin and Anchor CATs
                Clusters::JointFabricDatastore::Commands::AddGroup::DecodableType addGroupCommandData;
                addGroupCommandData.groupID       = 0;
                addGroupCommandData.friendlyName  = "Default JFA Group"_span;
                addGroupCommandData.groupKeySetID = 0;
                addGroupCommandData.groupCAT      = kAdminCATIdentifier; // Use Admin CAT for default group
                addGroupCommandData.groupCATVersion.SetNonNull(1);
                addGroupCommandData.groupPermission =
                    Clusters::JointFabricDatastore::DatastoreAccessControlEntryPrivilegeEnum::kAdminister;
                LogErrorOnFailure(Server::GetInstance().GetJointFabricDatastore().ForceAddGroup(addGroupCommandData));
                addGroupCommandData.groupID  = 1;
                addGroupCommandData.groupCAT = kAnchorCATIdentifier; // Use Anchor CAT for second default group
                LogErrorOnFailure(Server::GetInstance().GetJointFabricDatastore().ForceAddGroup(addGroupCommandData));

                Clusters::JointFabricDatastore::Structs::DatastoreAdministratorInformationEntryStruct::Type newAdmin;
                newAdmin.nodeID       = nodeId;
                newAdmin.friendlyName = "Default JFA Admin"_span;
                newAdmin.vendorID     = vendorId;
                newAdmin.icac         = ByteSpan(mICACBuffer, mICACBufferLen);

                LogErrorOnFailure(Server::GetInstance().GetJointFabricDatastore().AddAdmin(newAdmin));

                if (!mCommissionerInitialized)
                {
                    CHIP_ERROR err = InitCommissioner(LinuxDeviceOptions::GetInstance().securedCommissionerPort,
                                                      LinuxDeviceOptions::GetInstance().unsecuredCommissionerPort, fb.GetFabricId(),
                                                      fabricIndex);
                    if (err == CHIP_NO_ERROR)
                    {
                        mCommissionerInitialized = true;
                        ChipLogProgress(JointFabric, "Commissioner mode initialized on commissioned fabric index %u",
                                        static_cast<unsigned>(fabricIndex));
                    }
                    else
                    {
                        ChipLogError(JointFabric, "Failed to initialize commissioner mode: %" CHIP_ERROR_FORMAT, err.Format());
                    }
                }

                ChipLogProgress(JointFabric, "Joint Fabric Administrator commissioned on fabric index %d", fabricIndex);
            }
        }
    }
}

bool JFAManager::IsDeviceJFAdmin()
{
    if (jfFabricIndex == kUndefinedFabricId)
    {
        return false;
    }

    CATValues cats;

    if (mServer->GetFabricTable().FetchCATs(jfFabricIndex, cats) == CHIP_NO_ERROR)
    {
        if (cats.ContainsIdentifier(kAdminCATIdentifier))
        {
            return true;
        }
    }

    return false;
}

bool JFAManager::IsDeviceJFAnchor()
{
    if (jfFabricIndex == kUndefinedFabricId)
    {
        return false;
    }

    CATValues cats;

    if (mServer->GetFabricTable().FetchCATs(jfFabricIndex, cats) == CHIP_NO_ERROR)
    {
        if (cats.ContainsIdentifier(kAnchorCATIdentifier))
        {
            return true;
        }
    }

    return false;
}

void JFAManager::ReleaseSession()
{
    auto optionalSessionHandle = mSessionHolder.Get();

    if (optionalSessionHandle.HasValue())
    {
        if (optionalSessionHandle.Value()->IsActiveSession())
        {
            optionalSessionHandle.Value()->AsSecureSession()->MarkAsDefunct();
        }
    }
    mSessionHolder.Release();
}

void JFAManager::ConnectToNode(ScopedNodeId scopedNodeId, OnConnectedAction onConnectedAction)
{
    VerifyOrDie(mServer != nullptr);

    if ((scopedNodeId.GetFabricIndex() == kUndefinedFabricIndex) || (scopedNodeId.GetNodeId() == kUndefinedNodeId))
    {
        ChipLogError(JointFabric, "Invalid node location!");
        return;
    }

    // Set the action to take once connection is successfully established
    mNodeId            = scopedNodeId.GetNodeId();
    mOnConnectedAction = onConnectedAction;

    ChipLogDetail(JointFabric, "Establishing session to node ID 0x" ChipLogFormatX64 " on fabric index %d",
                  ChipLogValueX64(scopedNodeId.GetNodeId()), scopedNodeId.GetFabricIndex());

    mCASESessionManager->FindOrEstablishSession(scopedNodeId, &mOnConnectedCallback, &mOnConnectionFailureCallback);
}

void JFAManager::OnConnected(void * context, Messaging::ExchangeManager & exchangeMgr, const SessionHandle & sessionHandle)
{
    JFAManager * jfaManager = static_cast<JFAManager *>(context);

    VerifyOrDie(jfaManager != nullptr);
    jfaManager->mSessionHolder.Grab(sessionHandle);
    jfaManager->mExchangeMgr = &exchangeMgr;

    ChipLogProgress(JointFabric, "Established CASE");

    switch (jfaManager->mOnConnectedAction)
    {
    case kStandardCommissioningComplete: {
        TEMPORARY_RETURN_IGNORED jfaManager->SendCommissioningComplete();
        break;
    }
    case kJCMCommissioning: {
        TEMPORARY_RETURN_IGNORED jfaManager->AnnounceJointFabricAdministrator();
        break;
    }
    case kReadJointFabricIpk: {
        if (jfaManager->ReadJointFabricIpk() != CHIP_NO_ERROR)
        {
            jfaManager->NotifyJointFabricJoined(ByteSpan());
            jfaManager->ReleaseSession();
        }
        break;
    }

    default:
        break;
    }
}

void JFAManager::OnConnectionFailure(void * context, const ScopedNodeId & peerId, CHIP_ERROR error)
{
    JFAManager * jfaManager = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManager != nullptr);

    ChipLogError(JointFabric, "Failed to establish connection to 0x" ChipLogFormatX64 " on fabric index %d",
                 ChipLogValueX64(peerId.GetNodeId()), peerId.GetFabricIndex());

    if (jfaManager->mOnConnectedAction == kReadJointFabricIpk)
    {
        // Still tell JFC about the fabric: without the IPK it cannot act on it, and says so.
        jfaManager->NotifyJointFabricJoined(ByteSpan());
    }
    jfaManager->ReleaseSession();
}

CHIP_ERROR JFAManager::AnnounceJointFabricAdministrator()
{
    Commands::AnnounceJointFabricAdministrator::Type request;

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(JointFabric, "AnnounceJointFabricAdministrator: invoke cluster command.");
    request.endpointID = kJointFabricAdminEndpointId;

    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), peerAdminJFAdminClusterEndpointId);
    return cluster.InvokeCommand(request, this, OnAnnounceJointFabricAdministratorResponse,
                                 OnAnnounceJointFabricAdministratorFailure);
}

void JFAManager::OnAnnounceJointFabricAdministratorResponse(void * context, const chip::app::DataModel::NullObjectType & data)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);

    ChipLogProgress(JointFabric, "OnAnnounceJointFabricAdministratorResponse");

    /* TODO: https://github.com/project-chip/connectedhomeip/issues/38202 */
    TEMPORARY_RETURN_IGNORED jfaManagerCore->SendICACSRRequest();
}

void JFAManager::OnAnnounceJointFabricAdministratorFailure(void * context, CHIP_ERROR error)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);
    jfaManagerCore->ReleaseSession();

    ChipLogError(JointFabric, "OnAnnounceJointFabricAdministratorFailure: %s\n", chip::ErrorStr(error));
}

CHIP_ERROR JFAManager::SendICACSRRequest()
{
    Commands::ICACCSRRequest::Type request;

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(JointFabric, "SendICACSRRequest: invoke cluster command.");

    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), peerAdminJFAdminClusterEndpointId);
    return cluster.InvokeCommand(request, this, OnSendICACSRRequestResponse, OnSendICACSRRequestFailure);
}

void JFAManager::OnSendICACSRRequestResponse(void * context, const Commands::ICACCSRResponse::DecodableType & icaccsr)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);
    P256PublicKey pubKey;

    ChipLogProgress(JointFabric, "OnSendICACSRRequestResponse");

    if (icaccsr.icaccsr.HasValue() &&
        (CHIP_NO_ERROR ==
         VerifyCertificateSigningRequest(icaccsr.icaccsr.Value().data(), icaccsr.icaccsr.Value().size(), pubKey)) &&
        jfaManagerCore->peerAdminICACPubKey.Matches(pubKey))
    {
        ChipLogProgress(JointFabric, "OnSendICACSRRequestResponse: validated ICAC CSR");

        // ICAC cross-signing (spec 12.2.5.4): JFC, which holds the anchor root key, signs the peer's ICAC CSR; the
        // peer gets it through AddICAC. CommissioningComplete follows once the peer accepted it.
        JFARpc * jfaRpc = jfaManagerCore->GetJFARpc();
        const FabricInfo * fabric = jfaManagerCore->mServer->GetFabricTable().FindFabricWithIndex(
            static_cast<FabricIndex>(jfaManagerCore->jfFabricIndex));
        uint8_t icacBuf[Credentials::kMaxCHIPCertLength];
        MutableByteSpan icac(icacBuf);
        if (jfaRpc != nullptr && fabric != nullptr &&
            jfaRpc->GetCrossSignedICACForJF(icaccsr.icaccsr.Value(), fabric->GetFabricId(), icac) == CHIP_NO_ERROR &&
            jfaManagerCore->SendAddICAC(icac) == CHIP_NO_ERROR)
        {
            return;
        }
        ChipLogError(JointFabric, "OnSendICACSRRequestResponse: could not cross-sign the peer's ICAC");
    }
    jfaManagerCore->ReleaseSession();
}

CHIP_ERROR JFAManager::SendAddICAC(const ByteSpan & icac)
{
    Commands::AddICAC::Type request;

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(JointFabric, "SendAddICAC: invoke cluster command.");
    request.ICACValue = icac;

    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), peerAdminJFAdminClusterEndpointId);
    return cluster.InvokeCommand(request, this, OnAddICACResponse, OnAddICACFailure);
}

void JFAManager::OnAddICACResponse(void * context, const Commands::ICACResponse::DecodableType & response)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);

    if (response.statusCode != ICACResponseStatusEnum::kOk)
    {
        ChipLogError(JointFabric, "OnAddICACResponse: the peer refused the cross-signed ICAC, status %u",
                     to_underlying(response.statusCode));
        jfaManagerCore->ReleaseSession();
        return;
    }

    ChipLogProgress(JointFabric, "OnAddICACResponse: cross-signed ICAC accepted");
    TEMPORARY_RETURN_IGNORED jfaManagerCore->SendCommissioningComplete();
}

void JFAManager::OnAddICACFailure(void * context, CHIP_ERROR error)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);
    jfaManagerCore->ReleaseSession();

    ChipLogError(JointFabric, "OnAddICACFailure: %s\n", chip::ErrorStr(error));
}

void JFAManager::OnCrossSignedIcacAccepted(FabricIndex fabricIndex, const ByteSpan & icac, NodeId peerAdminNodeId,
                                           EndpointId peerAdminEndpointId)
{
    if (icac.size() > sizeof(mPendingJoin.icac))
    {
        ChipLogError(JointFabric, "Cross-signed ICAC too large (%u bytes)", static_cast<unsigned>(icac.size()));
        return;
    }
    ChipLogProgress(JointFabric, "Cross-signed ICAC accepted for fabric index %u; awaiting CommissioningComplete",
                    static_cast<unsigned>(fabricIndex));
    mPendingJoin.active      = true;
    mPendingJoin.fabricIndex = fabricIndex;
    memcpy(mPendingJoin.icac, icac.data(), icac.size());
    mPendingJoin.icacLen      = icac.size();
    mPendingJoin.peerNodeId   = peerAdminNodeId;
    mPendingJoin.peerEndpoint = peerAdminEndpointId;
}

CHIP_ERROR JFAManager::ReadJointFabricIpk()
{
    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(JointFabric, "ReadJointFabricIpk: reading the anchor's GroupKeySetList.");
    // The anchor publishes its IPK epoch key as datastore keyset 0 (readable with Administer, which the Administrator
    // CAT grants); the reference anchor leaves it empty.
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), mPendingJoin.peerEndpoint);
    return cluster.ReadAttribute<Clusters::JointFabricDatastore::Attributes::GroupKeySetList::TypeInfo>(
        this, OnGroupKeySetListRead, OnGroupKeySetListReadFailure);
}

void JFAManager::OnGroupKeySetListRead(
    void * context,
    const DataModel::DecodableList<Clusters::JointFabricDatastore::Structs::DatastoreGroupKeySetStruct::DecodableType> & keySets)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);

    uint8_t ipkBuf[Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];
    ByteSpan ipk;
    auto it = keySets.begin();
    while (it.Next())
    {
        const auto & keySet = it.GetValue();
        if (keySet.groupKeySetID == Credentials::GroupDataProvider::kIdentityProtectionKeySetId && !keySet.epochKey0.IsNull() &&
            keySet.epochKey0.Value().size() == sizeof(ipkBuf))
        {
            memcpy(ipkBuf, keySet.epochKey0.Value().data(), sizeof(ipkBuf));
            ipk = ByteSpan(ipkBuf);
        }
    }
    if (it.GetStatus() != CHIP_NO_ERROR || ipk.empty())
    {
        ChipLogError(JointFabric, "The anchor's datastore holds no IPK epoch key");
    }

    jfaManagerCore->NotifyJointFabricJoined(ipk);
    jfaManagerCore->ReleaseSession();
}

void JFAManager::OnGroupKeySetListReadFailure(void * context, CHIP_ERROR error)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);

    ChipLogError(JointFabric, "OnGroupKeySetListReadFailure: %s\n", chip::ErrorStr(error));
    jfaManagerCore->NotifyJointFabricJoined(ByteSpan());
    jfaManagerCore->ReleaseSession();
}

void JFAManager::NotifyJointFabricJoined(const ByteSpan & ipkEpochKey)
{
    if (!mPendingJoin.active)
    {
        return;
    }
    mPendingJoin.active = false;

    const FabricIndex fabricIndex = mPendingJoin.fabricIndex;
    const FabricInfo * fabric     = mServer->GetFabricTable().FindFabricWithIndex(fabricIndex);
    if (fabric == nullptr)
    {
        ChipLogError(JointFabric, "Joined fabric index %u is gone", static_cast<unsigned>(fabricIndex));
        return;
    }

    JoinedFabricInfo joined;
    joined.fabricIndex     = fabricIndex;
    joined.fabricId        = fabric->GetFabricId();
    joined.vendorId        = fabric->GetVendorId();
    joined.crossSignedIcac = ByteSpan(mPendingJoin.icac, mPendingJoin.icacLen);
    joined.ipkEpochKey     = ipkEpochKey;
    joined.anchorNodeId    = mPendingJoin.peerNodeId;
    joined.anchorEndpoint  = mPendingJoin.peerEndpoint;

    CATValues cats;
    if (mServer->GetFabricTable().FetchCATs(fabricIndex, cats) == CHIP_NO_ERROR)
    {
        for (CASEAuthTag cat : cats.values)
        {
            if (cat != kUndefinedCAT && GetCASEAuthTagIdentifier(cat) == kAdminCATIdentifier)
            {
                joined.adminCat = cat;
            }
        }
    }

    // Spec 12.2.5 step 9: the joined fabric is now this administrator's joint fabric.
    (void) app::Clusters::JointFabricAdministrator::Attributes::AdministratorFabricIndex::Set(kJointFabricAdminEndpointId,
                                                                                            fabricIndex);

    JFARpc * jfaRpc = GetJFARpc();
    if (jfaRpc == nullptr || jfaRpc->NotifyJointFabricJoined(joined) != CHIP_NO_ERROR)
    {
        ChipLogError(JointFabric, "Could not tell JFC about joined fabric index %u", static_cast<unsigned>(fabricIndex));
    }
}

void JFAManager::OnSendICACSRRequestFailure(void * context, CHIP_ERROR error)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);
    jfaManagerCore->ReleaseSession();

    ChipLogError(JointFabric, "OnSendICACSRRequestFailure: %s\n", chip::ErrorStr(error));
}

CHIP_ERROR JFAManager::SendCommissioningComplete()
{
    GeneralCommissioning::Commands::CommissioningComplete::Type request;

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(JointFabric, "SendCommissioningComplete: invoke cluster command.");
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.InvokeCommand(request, this, OnCommissioningCompleteResponse, OnCommissioningCompleteFailure);
}

void JFAManager::OnCommissioningCompleteResponse(
    void * context, const GeneralCommissioning::Commands::CommissioningCompleteResponse::DecodableType & data)
{
    JFAManager * jfaManager = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManager != nullptr);

    ChipLogProgress(JointFabric, "OnCommissioningCompleteResponse, Code=%u", to_underlying(data.errorCode));

    if (data.errorCode != GeneralCommissioning::CommissioningErrorEnum::kOk)
    {
        ChipLogProgress(JointFabric, "Commssioning Failed (nodeId=%ld, isJCM = %d), Code=%u", jfaManager->mNodeId,
                        jfaManager->mOnConnectedAction == kJCMCommissioning, to_underlying(data.errorCode));
    }
    else
    {
        switch (jfaManager->mOnConnectedAction)
        {
        case kStandardCommissioningComplete: {
            ChipLogProgress(JointFabric, "Standard Commissioning (nodeId=%ld) success", jfaManager->mNodeId);
            break;
        }
        case kJCMCommissioning: {
            ChipLogProgress(JointFabric, "Joint Commissioning Method (nodeId=%ld) success", jfaManager->mNodeId);
            break;
        }
        }
    }

    jfaManager->ReleaseSession();
}

void JFAManager::OnCommissioningCompleteFailure(void * context, CHIP_ERROR error)
{
    JFAManager * jfaManagerCore = static_cast<JFAManager *>(context);
    VerifyOrDie(jfaManagerCore != nullptr);
    jfaManagerCore->ReleaseSession();

    ChipLogError(JointFabric, "Received failure response %s\n", chip::ErrorStr(error));
}

CHIP_ERROR JFAManager::GetIcacCsr(MutableByteSpan & icacCsr)
{
    JFARpc * jfaRpc = GetJFARpc();

    if (jfaRpc)
    {
        return jfaRpc->GetICACCSRForJF(icacCsr);
    }

    return CHIP_ERROR_UNINITIALIZED;
}
