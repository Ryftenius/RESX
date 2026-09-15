#define WIN32_LEAN_AND_MEAN
#define UM_NDIS650
#include <windows.h>
#include <ndis/oidrequest.h>
#include <stddef.h>

/* Static-only inputs linked to WDK imports. Never load or submit these requests.
   SDK declarations independently check the offsets RESX uses. */
C_ASSERT(sizeof(void *) == 8);
C_ASSERT(offsetof(NDIS_OID_REQUEST, RequestType) == 4);
C_ASSERT(offsetof(NDIS_OID_REQUEST, PortNumber) == 8);
C_ASSERT(offsetof(NDIS_OID_REQUEST, Timeout) == 12);
C_ASSERT(offsetof(NDIS_OID_REQUEST, RequestId) == 16);
C_ASSERT(offsetof(NDIS_OID_REQUEST, RequestHandle) == 24);
C_ASSERT(offsetof(NDIS_OID_REQUEST, DATA.QUERY_INFORMATION.Oid) == 32);
C_ASSERT(offsetof(NDIS_OID_REQUEST, DATA.QUERY_INFORMATION.InformationBuffer) == 40);
C_ASSERT(offsetof(NDIS_OID_REQUEST, DATA.QUERY_INFORMATION.InformationBufferLength) == 48);
C_ASSERT(offsetof(NDIS_OID_REQUEST, DATA.METHOD_INFORMATION.OutputBufferLength) == 52);
C_ASSERT(offsetof(NDIS_OID_REQUEST, DATA.METHOD_INFORMATION.MethodId) == 56);
C_ASSERT(NDIS_SIZEOF_OID_REQUEST_REVISION_1 == 236);
C_ASSERT(NDIS_SIZEOF_OID_REQUEST_REVISION_2 == 248);
C_ASSERT(sizeof(NDIS_OID_REQUEST) == 248);

__declspec(dllimport) NDIS_STATUS NdisOidRequest(NDIS_HANDLE handle, PNDIS_OID_REQUEST request);
__declspec(dllimport) NDIS_STATUS NdisFOidRequest(NDIS_HANDLE handle, PNDIS_OID_REQUEST request);

__declspec(dllexport) NDIS_STATUS ResxNdisQuery(NDIS_HANDLE handle, void *buffer)
{
    volatile NDIS_OID_REQUEST request = {0};
    request.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    request.Header.Revision = NDIS_OID_REQUEST_REVISION_2;
    request.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_2;
    request.RequestType = NdisRequestQueryInformation;
    request.DATA.QUERY_INFORMATION.Oid = 0x00010101;
    request.DATA.QUERY_INFORMATION.InformationBuffer = buffer;
    request.DATA.QUERY_INFORMATION.InformationBufferLength = 32;
    return NdisOidRequest(handle, (PNDIS_OID_REQUEST)&request);
}

__declspec(dllexport) NDIS_STATUS ResxNdisMethod(NDIS_HANDLE handle, void *buffer)
{
    volatile NDIS_OID_REQUEST request = {0};
    request.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    request.Header.Revision = NDIS_OID_REQUEST_REVISION_2;
    request.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_2;
    request.RequestType = NdisRequestMethod;
    request.DATA.METHOD_INFORMATION.Oid = 0x01010102;
    request.DATA.METHOD_INFORMATION.InformationBuffer = buffer;
    request.DATA.METHOD_INFORMATION.InputBufferLength = 12;
    request.DATA.METHOD_INFORMATION.OutputBufferLength = 64;
    request.DATA.METHOD_INFORMATION.MethodId = 7;
    return NdisFOidRequest(handle, (PNDIS_OID_REQUEST)&request);
}

__declspec(dllexport) NDIS_STATUS ResxNdisWrongHeader(NDIS_HANDLE handle)
{
    volatile NDIS_OID_REQUEST request = {0};
    request.Header.Type = 0x95; /* An OID-shaped value is insufficient. */
    request.Header.Revision = NDIS_OID_REQUEST_REVISION_2;
    request.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_2;
    request.RequestType = NdisRequestQueryInformation;
    request.DATA.QUERY_INFORMATION.Oid = 0x00010101;
    return NdisOidRequest(handle, (PNDIS_OID_REQUEST)&request);
}
