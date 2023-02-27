### rfc3161-timestamping
Implementation of [IETF RFC3161](https://www.ietf.org/rfc/rfc3161.txt) Timestamping using C#/.NET

This example uses [RFC3161TimestampRequest](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamprequest), [Rfc3161TimestampToken](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptoken) and [Rfc3161TimestampTokenInfo](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptokeninfo) from [System.Security.Cryptography.Pkcs Namespace](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs).

I decided to share this example, due to a serious lack of documentation and examples for timestaming using pure .NET. Most of the examples I found used third party libraries. I also included a JsonConverter that serializes a RFC3161TimestampToken so it can be saved to.

My example uses HTTP as the transmission protocol between the user and the timestamping authority. TAs public key is received with the timestamp response.
