using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using Nimbis.FolderSign.Logging;
using Nimbis.FolderSign.Misc;

namespace Nimbis.FolderSign.Timestamping;

/// <summary>
/// A RFC3161 Timestamp of a hash value.
/// </summary>
public class Timestamping
{
    private static readonly HttpClient HttpClient = new HttpClient();
    private static readonly String RequestContentType = "application/timestamp-query";
    private static readonly String ResponseContentType = "application/timestamp-reply";
    private static readonly String TimestampAuthorityUrl = "https://freetsa.org/tsr";

    /// <summary>
    /// Requests a RFC3161 Timestamp from https://freetsa.org/tsr.
    /// Timestamping works in accordance with RFC3161(https://www.ietf.org/rfc/rfc3161.txt). HTTP is used as the
    /// transport protocol.
    /// </summary>
    /// <param name="hash">A string representation of a hash value</param>
    /// <param name="hashAlgorithmName">The hashing algorithm used when generating <paramref name="hash"/></param>
    /// <returns>An instance of Rfc3161TimestampToken</returns>
    /// <exception cref="Exception"></exception>
    public static Rfc3161TimestampToken RequestTimestampTokenForHash(byte[] hash, HashAlgorithmName hashAlgorithmName)
    {
        // A random nonce
        byte[] nonce = CryptoUtils.GetNonce(20);
        
        // Creating Rfc3161TimestampRequest instance, which will be used as the HTTP POST payload
        Rfc3161TimestampRequest timestampRequest =
            Rfc3161TimestampRequest.CreateFromHash(
                hash,
                hashAlgorithmName,
                null,
                nonce,
                true);

        // Construct HttpContent
        byte[] timestampRequestBytes = timestampRequest.Encode();
        using StreamContent streamContent = new StreamContent(new MemoryStream(timestampRequestBytes));
        streamContent
            .Headers
            .ContentType = new MediaTypeHeaderValue(RequestContentType);

        // Construct a HttpRequestMessage
        using HttpRequestMessage httpRequestMessage = new HttpRequestMessage();
        httpRequestMessage.RequestUri = new Uri(TimestampAuthorityUrl);
        httpRequestMessage.Method = HttpMethod.Post;
        httpRequestMessage.Content = streamContent;

        // Send the request and wait for a response
        using HttpResponseMessage httpResponseMessage = HttpClient.Send(httpRequestMessage);
        MediaTypeHeaderValue contentType = httpRequestMessage.Content.Headers.ContentType;

        if (httpResponseMessage.StatusCode != HttpStatusCode.OK)
            throw new Exception($"Timestamp Server returned a {httpResponseMessage.StatusCode} response");

        if (contentType is null)
            throw new Exception("Content-Type of Response can't be null");

        if (contentType.MediaType!.Equals(ResponseContentType))
            throw new Exception($"Invalid response Content-Type: {contentType.MediaType}");

        byte[] timestampResponseBytes = StreamUtil.GetStreamBytes(httpResponseMessage.Content.ReadAsStream());

        int bytesConsumed;
        Rfc3161TimestampToken timestampToken =
            timestampRequest.ProcessResponse(timestampResponseBytes, out bytesConsumed);

        X509Certificate2? timestampAuthorityCertificate;
        if (!timestampToken.VerifySignatureForHash(hashBytes, hashAlgorithmName, out timestampAuthorityCertificate))
            throw new Exception(
                $"Timestamp could not be verified for hash({hashAlgorithmName.Name}: {CryptoUtils.BytesToHexString(hash)})");

        return timestampToken;
    }
}
