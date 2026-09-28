#include "pigweed/rpc_services/JointFabric.h"

#include <app/server/CommissioningWindowManager.h>
#include <app/server/Server.h>
#include <lib/support/logging/CHIPLogging.h>

#include <cstring>

using namespace chip;

namespace joint_fabric_service {

constexpr uint32_t kRpcTimeoutMs = 1000;
std::condition_variable responseCv;
std::mutex responseMutex;
bool responseReceived = false;

// The last ResponseStream payload: an ICAC CSR (DER) or a cross-signed ICAC (Matter TLV). Sized for the
// largest (Response.response_bytes max_size in joint_fabric_service.options).
uint8_t responseBuf[600] = { 0 };
size_t responseLen       = 0;

::pw::Status JointFabric::TransferOwnership(const ::OwnershipContext & request, ::pw_protobuf_Empty & response)
{
    ChipLogProgress(JointFabric, "RPC Ownership Transfer for NodeId: 0x" ChipLogFormatX64 ", jcm=%d",
                    ChipLogValueX64(request.node_id), request.jcm);

    if (request.jcm && (Crypto::kP256_PublicKey_Length != request.trustedIcacPublicKeyB.size))
    {
        ChipLogError(JointFabric, "Invalid ICAC Public Key Size");
        return pw::Status::OutOfRange();
    }

    if (request.jcm && request.peerAdminJFAdminClusterEndpointId == kInvalidEndpointId)
    {
        ChipLogError(JointFabric, "Invalid Peer Admin Endpoint ID for the JF Administrator Cluster");
        return pw::Status::OutOfRange();
    }

    OwnershipTransferContext * data = Platform::New<OwnershipTransferContext>(
        request.node_id, request.jcm, ByteSpan(request.trustedIcacPublicKeyB.bytes, request.trustedIcacPublicKeyB.size),
        request.peerAdminJFAdminClusterEndpointId);
    VerifyOrReturnValue(data, pw::Status::Internal());
    TEMPORARY_RETURN_IGNORED DeviceLayer::PlatformMgr().ScheduleWork(FinalizeCommissioningWork, reinterpret_cast<intptr_t>(data));

    return pw::OkStatus();
}

void JointFabric::GetStream(const ::pw_protobuf_Empty & request, ServerWriter<::RequestOptions> & writer)
{
    ChipLogProgress(JointFabric, "GetStream Opened");
    rpcGetStream = std::move(writer);

    return;
}

::pw::Status JointFabric::ResponseStream(const ::Response & responseBytes, ::pw_protobuf_Empty & response)
{
    ChipLogProgress(JointFabric, "RPC ResponseStream (%u bytes)", static_cast<unsigned>(responseBytes.response_bytes.size));

    {
        std::lock_guard<std::mutex> lock(responseMutex);
        if (responseBytes.response_bytes.size > sizeof(responseBuf))
        {
            return pw::Status::OutOfRange();
        }
        memcpy(responseBuf, responseBytes.response_bytes.bytes, responseBytes.response_bytes.size);
        responseLen      = responseBytes.response_bytes.size;
        responseReceived = true;
    }
    responseCv.notify_one();

    return pw::OkStatus();
}

CHIP_ERROR JointFabric::Request(const ::RequestOptions & requestOptions, MutableByteSpan & out)
{
    std::unique_lock<std::mutex> lock(responseMutex);
    responseReceived = false;

    if (pw::OkStatus() != rpcGetStream.Write(requestOptions))
    {
        ChipLogError(JointFabric, "Writing to GetStream failed");
        return CHIP_ERROR_SHUT_DOWN;
    }

    // wait for JFC's answer
    if (!responseCv.wait_for(lock, std::chrono::milliseconds(kRpcTimeoutMs), [] { return responseReceived; }))
    {
        return CHIP_ERROR_TIMEOUT;
    }
    responseReceived = false;
    return CopySpanToMutableSpan(ByteSpan(responseBuf, responseLen), out);
}

CHIP_ERROR JointFabric::GetICACCSRForJF(MutableByteSpan & icacCSR)
{
    // JFA requests an ICAC CSR from JFC
    ::RequestOptions requestOptions = RequestOptions_init_zero;
    requestOptions.transaction_type = TransactionType::TransactionType_ICAC_CSR;
    return Request(requestOptions, icacCSR);
}

CHIP_ERROR JointFabric::GetCrossSignedICACForJF(const ByteSpan & icacCSR, FabricId anchorFabricId, MutableByteSpan & icac)
{
    ::RequestOptions requestOptions = RequestOptions_init_zero;
    requestOptions.transaction_type = TransactionType::TransactionType_CROSS_SIGNED_ICAC;
    requestOptions.anchor_fabric_id = anchorFabricId;
    VerifyOrReturnError(icacCSR.size() <= sizeof(requestOptions.csr.bytes), CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(requestOptions.csr.bytes, icacCSR.data(), icacCSR.size());
    requestOptions.csr.size = static_cast<pb_size_t>(icacCSR.size());
    return Request(requestOptions, icac);
}

CHIP_ERROR JointFabric::NotifyJointFabricJoined(const JoinedFabricInfo & joined)
{
    ::RequestOptions requestOptions = RequestOptions_init_zero;
    requestOptions.transaction_type = TransactionType::TransactionType_JOINT_FABRIC_JOINED;
    requestOptions.has_joined       = true;

    ::JoinedFabric & info = requestOptions.joined;
    info.fabric_index     = joined.fabricIndex;
    info.fabric_id        = joined.fabricId;
    info.vendor_id        = to_underlying(joined.vendorId);
    info.admin_cat        = joined.adminCat;
    info.anchor_node_id   = joined.anchorNodeId;
    info.anchor_endpoint  = joined.anchorEndpoint;
    VerifyOrReturnError(joined.crossSignedIcac.size() <= sizeof(info.cross_signed_icac.bytes), CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(info.cross_signed_icac.bytes, joined.crossSignedIcac.data(), joined.crossSignedIcac.size());
    info.cross_signed_icac.size = static_cast<pb_size_t>(joined.crossSignedIcac.size());
    VerifyOrReturnError(joined.ipkEpochKey.size() <= sizeof(info.ipk_epoch_key.bytes), CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(info.ipk_epoch_key.bytes, joined.ipkEpochKey.data(), joined.ipkEpochKey.size());
    info.ipk_epoch_key.size = static_cast<pb_size_t>(joined.ipkEpochKey.size());

    // A notification: JFC answers with an empty ResponseStream, which is not waited for.
    if (pw::OkStatus() != rpcGetStream.Write(requestOptions))
    {
        ChipLogError(JointFabric, "Writing the joined fabric to GetStream failed");
        return CHIP_ERROR_SHUT_DOWN;
    }
    return CHIP_NO_ERROR;
}

void JointFabric::CloseStreams()
{
    rpcGetStream.Finish();
}

} // namespace joint_fabric_service
