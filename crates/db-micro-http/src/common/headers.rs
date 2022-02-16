// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::result::Result;

use crate::HttpHeaderError;
use crate::RequestError;

/// Wrapper over an HTTP Header type.
#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Header {
    /// Header `Content-Length`.
    ContentLength,
    /// Header `Content-Type`.
    ContentType,
    /// Header `Expect`.
    Expect,
    /// Header `Transfer-Encoding`.
    TransferEncoding,
    /// Header `Server`.
    Server,
    /// Header `Accept`
    Accept,
    /// Header `Accept-Encoding`
    AcceptEncoding,
}

impl Header {
    /// Returns a byte slice representation of the object.
    pub fn raw(&self) -> &'static [u8] {
        match self {
            Self::ContentLength => b"Content-Length",
            Self::ContentType => b"Content-Type",
            Self::Expect => b"Expect",
            Self::TransferEncoding => b"Transfer-Encoding",
            Self::Server => b"Server",
            Self::Accept => b"Accept",
            Self::AcceptEncoding => b"Accept-Encoding",
        }
    }

    /// Parses a byte slice into a Header structure. Header must be ASCII, so also
    /// UTF-8 valid.
    ///
    /// # Errors
    /// `InvalidRequest` is returned if slice contains invalid utf8 characters.
    /// `InvalidHeader` is returned if unsupported header found.
    fn try_from(string: &[u8]) -> Result<Self, RequestError> {
        if let Ok(mut utf8_string) = String::from_utf8(string.to_vec()) {
            utf8_string.make_ascii_lowercase();
            match utf8_string.trim() {
                "content-length" => Ok(Self::ContentLength),
                "content-type" => Ok(Self::ContentType),
                "expect" => Ok(Self::Expect),
                "transfer-encoding" => Ok(Self::TransferEncoding),
                "server" => Ok(Self::Server),
                "accept" => Ok(Self::Accept),
                "accept-encoding" => Ok(Self::AcceptEncoding),
                invalid_key => Err(RequestError::HeaderError(HttpHeaderError::UnsupportedName(
                    invalid_key.to_string(),
                ))),
            }
        } else {
            Err(RequestError::InvalidRequest)
        }
    }
}

/// Wrapper over the list of headers associated with a Request that we need
/// in order to parse the request correctly and be able to respond to it.
///
/// The only `Content-Type`s supported are `text/plain` and `application/json`, which are both
/// in plain text actually and don't influence our parsing process.
///
/// All the other possible header fields are not necessary in order to serve this connection
/// and, thus, are not of interest to us. However, we still look for header fields that might
/// invalidate our request as we don't support the full set of HTTP/1.1 specification.
/// Such header entries are "Transfer-Encoding: identity; q=0", which means a compression
/// algorithm is applied to the body of the request, or "Expect: 103-checkpoint".
#[derive(Debug, PartialEq)]
pub struct Headers {
    /// The `Content-Length` header field tells us how many bytes we need to receive
    /// from the source after the headers.
    content_length: u32,
    /// The `Expect` header field is set when the headers contain the entry "Expect: 100-continue".
    /// This means that, per HTTP/1.1 specifications, we must send a response with the status code
    /// 100 after we have received the headers in order to receive the body of the request. This
    /// field should be known immediately after parsing the headers.
    expect: bool,
    /// `Chunked` is a possible value of the `Transfer-Encoding` header field and every HTTP/1.1
    /// server must support it. It is useful only when receiving the body of the request and should
    /// be known immediately after parsing the headers.
    chunked: bool,
    /// `Accept` header might be used by HTTP clients to enforce server responses with content
    /// formatted in a specific way.
    accept: MediaType,
    /// Hashmap reserved for storing custom headers.
    custom_entries: HashMap<String, String>,
}

impl Default for Headers {
    /// By default Requests are created with no headers.
    fn default() -> Self {
        Self {
            content_length: Default::default(),
            expect: Default::default(),
            chunked: Default::default(),
            // The default `Accept` media type is plain text. This is inclusive enough
            // for structured and unstructured text.
            accept: MediaType::PlainText,
            custom_entries: HashMap::default(),
        }
    }
}

impl Headers {
    /// Expects one header line and parses it, updating the header structure or returning an
    /// error if the header is invalid.
    ///
    /// # Errors
    /// `UnsupportedHeader` is returned when the parsed header line is not of interest
    /// to us or when it is unrecognizable.
    /// `InvalidHeader` is returned when the parsed header is formatted incorrectly or suggests
    /// that the client is using HTTP features that we do not support in this implementation,
    /// which invalidates the request.
    ///
    /// # Examples
    ///
    /// ```
    /// use micro_http::Headers;
    ///
    /// let mut request_header = Headers::default();
    /// assert!(request_header.parse_header_line(b"Content-Length: 24").is_ok());
    /// assert!(request_header.parse_header_line(b"Content-Length: 24: 2").is_err());
    /// ```
    pub fn parse_header_line(&mut self, header_line: &[u8]) -> Result<(), RequestError> {
        // Headers must be ASCII, so also UTF-8 valid.
        match std::str::from_utf8(header_line) {
            Ok(headers_str) => {
                let entry = headers_str.splitn(2, ':').collect::<Vec<&str>>();
                if entry.len() != 2 {
                    return Err(RequestError::HeaderError(HttpHeaderError::InvalidFormat(
                        entry[0].to_string(),
                    )));
                }
                if let Ok(head) = Header::try_from(entry[0].as_bytes()) {
                    match head {
                        Header::ContentLength => match entry[1].trim().parse::<u32>() {
                            Ok(content_length) => {
                                self.content_length = content_length;
                                Ok(())
                            }
                            Err(_) => {
                                Err(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                                    entry[0].to_string(),
                                    entry[1].to_string(),
                                )))
                            }
                        },
                        Header::ContentType => {
                            match MediaType::try_from(entry[1].trim().as_bytes()) {
                                Ok(_) => Ok(()),
                                Err(_) => Err(RequestError::HeaderError(
                                    HttpHeaderError::UnsupportedValue(
                                        entry[0].to_string(),
                                        entry[1].to_string(),
                                    ),
                                )),
                            }
                        }
                        Header::Accept => match MediaType::try_from(entry[1].trim().as_bytes()) {
                            Ok(accept_type) => {
                                self.accept = accept_type;
                                Ok(())
                            }
                            Err(_) => Err(RequestError::HeaderError(
                                HttpHeaderError::UnsupportedValue(
                                    entry[0].to_string(),
                                    entry[1].to_string(),
                                ),
                            )),
                        },
                        Header::TransferEncoding => match entry[1].trim() {
                            "chunked" => {
                                self.chunked = true;
                                Ok(())
                            }
                            "identity" => Ok(()),
                            _ => Err(RequestError::HeaderError(
                                HttpHeaderError::UnsupportedValue(
                                    entry[0].to_string(),
                                    entry[1].to_string(),
                                ),
                            )),
                        },
                        Header::Expect => match entry[1].trim() {
                            "100-continue" => {
                                self.expect = true;
                                Ok(())
                            }
                            _ => Err(RequestError::HeaderError(
                                HttpHeaderError::UnsupportedValue(
                                    entry[0].to_string(),
                                    entry[1].to_string(),
                                ),
                            )),
                        },
                        Header::Server => Ok(()),
                        Header::AcceptEncoding => Encoding::try_from(entry[1].trim().as_bytes()),
                    }
                } else {
                    self.insert_custom_header(
                        entry[0].trim().to_string(),
                        entry[1].trim().to_string(),
                    )?;
                    Ok(())
                }
            }
            Err(utf8_err) => Err(RequestError::HeaderError(
                HttpHeaderError::InvalidUtf8String(utf8_err),
            )),
        }
    }

    /// Returns the content length of the body.
    pub fn content_length(&self) -> u32 {
        self.content_length
    }

    /// Returns `true` if the transfer encoding is chunked.
    #[allow(unused)]
    pub fn chunked(&self) -> bool {
        self.chunked
    }

    /// Returns `true` if the client is expecting the code 100.
    #[allow(unused)]
    pub fn expect(&self) -> bool {
        self.expect
    }

    /// Returns the `Accept` header `MediaType`.
    pub fn accept(&self) -> MediaType {
        self.accept
    }

    /// Parses a byte slice into a Headers structure for a HTTP request.
    ///
    /// The byte slice is expected to have the following format: </br>
    ///     * Request Header Lines "<header_line> CRLF"- Optional </br>
    /// There can be any number of request headers, including none, followed by
    /// an extra sequence of Carriage Return and Line Feed.
    /// All header fields are parsed. However, only the ones present in the
    /// [`Headers`](struct.Headers.html) struct are relevant to us and stored
    /// for future use.
    ///
    /// # Errors
    /// The function returns `InvalidHeader` when parsing the byte stream fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use micro_http::Headers;
    ///
    /// let request_headers = Headers::try_from(b"Content-Length: 55\r\n\r\n");
    /// ```
    pub fn try_from(bytes: &[u8]) -> Result<Headers, RequestError> {
        // Headers must be ASCII, so also UTF-8 valid.
        if let Ok(text) = std::str::from_utf8(bytes) {
            let mut headers = Self::default();

            let header_lines = text.split("\r\n");
            for header_line in header_lines {
                if header_line.is_empty() {
                    break;
                }
                match headers.parse_header_line(header_line.as_bytes()) {
                    Ok(_)
                    | Err(RequestError::HeaderError(HttpHeaderError::UnsupportedValue(_, _))) => {
                        continue
                    }
                    Err(e) => return Err(e),
                };
            }
            return Ok(headers);
        }
        Err(RequestError::InvalidRequest)
    }

    /// Accept header setter.
    pub fn set_accept(&mut self, media_type: MediaType) {
        self.accept = media_type;
    }

    /// Insert a new custom header and value pair into the `HashMap`.
    pub fn insert_custom_header(&mut self, key: String, value: String) -> Result<(), RequestError> {
        self.custom_entries.insert(key, value);
        Ok(())
    }

    /// Returns the custom header `HashMap`.
    pub fn custom_entries(&self) -> &HashMap<String, String> {
        &self.custom_entries
    }
}

/// Wrapper over supported AcceptEncoding.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Encoding {}

impl Encoding {
    /// Parses a byte slice and checks if identity encoding is invalidated. Encoding
    /// must be ASCII, so also UTF-8 valid.
    ///
    /// # Errors
    /// `InvalidRequest` is returned when the byte stream is empty.
    ///
    /// `InvalidValue` is returned when the identity encoding is invalidated.
    ///
    /// `InvalidUtf8String` is returned when the byte stream contains invalid characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use micro_http::Encoding;
    ///
    /// assert!(Encoding::try_from(b"deflate").is_ok());
    /// assert!(Encoding::try_from(b"identity;q=0").is_err());
    /// ```
    pub fn try_from(bytes: &[u8]) -> Result<(), RequestError> {
        if bytes.is_empty() {
            return Err(RequestError::InvalidRequest);
        }
        match std::str::from_utf8(bytes) {
            Ok(headers_str) => {
                let entry = headers_str.split(',').collect::<Vec<&str>>();

                for encoding in entry {
                    match encoding.trim() {
                        "identity;q=0" => {
                            Err(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                                "Accept-Encoding".to_string(),
                                encoding.to_string(),
                            )))
                        }
                        "*;q=0" if !headers_str.contains("identity") => {
                            Err(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                                "Accept-Encoding".to_string(),
                                encoding.to_string(),
                            )))
                        }
                        _ => Ok(()),
                    }?;
                }
                Ok(())
            }
            Err(utf8_err) => Err(RequestError::HeaderError(
                HttpHeaderError::InvalidUtf8String(utf8_err),
            )),
        }
    }
}

/// Wrapper over supported Media Types.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MediaType {
    /// Media Type: "text/plain".
    PlainText,
    /// Media Type: "application/json".
    ApplicationJson,
}

impl Default for MediaType {
    /// Default value for MediaType is application/json
    fn default() -> Self {
        Self::ApplicationJson
    }
}

impl MediaType {
    /// Parses a byte slice into a MediaType structure for a HTTP request. MediaType
    /// must be ASCII, so also UTF-8 valid.
    ///
    /// # Errors
    /// The function returns `InvalidRequest` when parsing the byte stream fails or
    /// unsupported MediaType found.
    ///
    /// # Examples
    ///
    /// ```
    /// use micro_http::MediaType;
    ///
    /// assert!(MediaType::try_from(b"application/json").is_ok());
    /// assert!(MediaType::try_from(b"application/json2").is_err());
    /// ```
    pub fn try_from(bytes: &[u8]) -> Result<Self, RequestError> {
        if bytes.is_empty() {
            return Err(RequestError::InvalidRequest);
        }
        let utf8_slice =
            String::from_utf8(bytes.to_vec()).map_err(|_| RequestError::InvalidRequest)?;
        match utf8_slice.as_str().trim() {
            "text/plain" => Ok(Self::PlainText),
            "application/json" => Ok(Self::ApplicationJson),
            _ => Err(RequestError::InvalidRequest),
        }
    }

    /// Returns a static string representation of the object.
    ///
    /// # Examples
    ///
    /// ```
    /// use micro_http::MediaType;
    ///
    /// let media_type = MediaType::ApplicationJson;
    /// assert_eq!(media_type.as_str(), "application/json");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlainText => "text/plain",
            Self::ApplicationJson => "application/json",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    impl Headers {
        pub fn new(content_length: u32, expect: bool, chunked: bool) -> Self {
            Self {
                content_length,
                expect,
                chunked,
                accept: MediaType::PlainText,
                custom_entries: HashMap::default(),
            }
        }
    }

    #[test]
    fn test_default() {
        let headers = Headers::default();
        assert_eq!(headers.content_length(), 0);
        assert!(!headers.chunked());
        assert!(!headers.expect());
        assert_eq!(headers.accept(), MediaType::PlainText);
        assert_eq!(headers.custom_entries(), &HashMap::default());
    }

    #[test]
    fn test_try_from_media() {
        assert_eq!(
            MediaType::try_from(b"application/json").unwrap(),
            MediaType::ApplicationJson
        );

        assert_eq!(
            MediaType::try_from(b"text/plain").unwrap(),
            MediaType::PlainText
        );

        assert_eq!(
            MediaType::try_from(b"").unwrap_err(),
            RequestError::InvalidRequest
        );

        assert_eq!(
            MediaType::try_from(b"application/json-patch").unwrap_err(),
            RequestError::InvalidRequest
        );
    }

    #[test]
    fn test_media_as_str() {
        let media_type = MediaType::ApplicationJson;
        assert_eq!(media_type.as_str(), "application/json");

        let media_type = MediaType::PlainText;
        assert_eq!(media_type.as_str(), "text/plain");
    }

    #[test]
    fn test_try_from_encoding() {
        assert_eq!(
            Encoding::try_from(b"").unwrap_err(),
            RequestError::InvalidRequest
        );

        assert_eq!(
            Encoding::try_from(b"identity;q=0").unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Accept-Encoding".to_string(),
                "identity;q=0".to_string()
            ))
        );

        assert!(Encoding::try_from(b"identity;q").is_ok());

        assert_eq!(
            Encoding::try_from(b"*;q=0").unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Accept-Encoding".to_string(),
                "*;q=0".to_string()
            ))
        );

        let bytes: [u8; 10] = [130, 140, 150, 130, 140, 150, 130, 140, 150, 160];
        assert!(Encoding::try_from(&bytes[..]).is_err());

        assert!(Encoding::try_from(b"identity;q=1").is_ok());
        assert!(Encoding::try_from(b"identity;q=0.1").is_ok());
        assert!(Encoding::try_from(b"deflate, identity, *;q=0").is_ok());
        assert!(Encoding::try_from(b"br").is_ok());
        assert!(Encoding::try_from(b"compress").is_ok());
        assert!(Encoding::try_from(b"gzip").is_ok());
    }

    #[test]
    fn test_try_from_headers() {
        // Valid headers.
        let headers =  Headers::try_from(
            b"Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\nAccept: application/json\r\nContent-Length: 55\r\n\r\n"
        )
            .unwrap();
        assert_eq!(headers.content_length, 55);
        assert_eq!(headers.accept, MediaType::ApplicationJson);
        assert_eq!(
            headers.custom_entries().get("Last-Modified").unwrap(),
            "Tue, 15 Nov 1994 12:45:26 GMT"
        );
        assert_eq!(headers.custom_entries().len(), 1);

        // Valid headers. (${HEADER_NAME} : WHITESPACE ${HEADER_VALUE})
        // Any number of whitespace characters should be accepted including zero.
        let headers =  Headers::try_from(
            b"Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\nAccept:text/plain\r\nContent-Length:   49\r\n\r\n"
        )
            .unwrap();
        assert_eq!(headers.content_length, 49);
        assert_eq!(headers.accept, MediaType::PlainText);

        // Valid headers.
        let headers = Headers::try_from(
            b"Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\nContent-Length: 29\r\n\r\n",
        )
        .unwrap();
        assert_eq!(headers.content_length, 29);

        // Custom headers only.
        let headers = Headers::try_from(
            b"Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\nfoo: bar\r\nbar: 15\r\n\r\n",
        )
        .unwrap();
        let custom_entries = headers.custom_entries();
        assert_eq!(custom_entries.get("foo").unwrap(), "bar");
        assert_eq!(custom_entries.get("bar").unwrap(), "15");
        assert_eq!(custom_entries.len(), 3);

        // Valid headers, invalid value.
        assert_eq!(
            Headers::try_from(
                b"Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\nContent-Length: -55\r\n\r\n"
            )
            .unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Content-Length".to_string(),
                " -55".to_string()
            ))
        );

        let bytes: [u8; 10] = [130, 140, 150, 130, 140, 150, 130, 140, 150, 160];
        // Invalid headers.
        assert!(Headers::try_from(&bytes[..]).is_err());
    }

    #[test]
    fn test_parse_header_line() {
        let mut header = Headers::default();

        // Invalid header syntax.
        assert_eq!(
            header.parse_header_line(b"Expect"),
            Err(RequestError::HeaderError(HttpHeaderError::InvalidFormat(
                "Expect".to_string()
            )))
        );

        // Invalid content length.
        assert_eq!(
            header.parse_header_line(b"Content-Length: five"),
            Err(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Content-Length".to_string(),
                " five".to_string()
            )))
        );

        // Invalid transfer encoding.
        assert_eq!(
            header.parse_header_line(b"Transfer-Encoding: gzip"),
            Err(RequestError::HeaderError(
                HttpHeaderError::UnsupportedValue(
                    "Transfer-Encoding".to_string(),
                    " gzip".to_string()
                )
            ))
        );

        // Invalid expect.
        assert_eq!(
            header
                .parse_header_line(b"Expect: 102-processing")
                .unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::UnsupportedValue(
                "Expect".to_string(),
                " 102-processing".to_string()
            ))
        );

        // Unsupported media type.
        assert_eq!(
            header
                .parse_header_line(b"Content-Type: application/json-patch")
                .unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::UnsupportedValue(
                "Content-Type".to_string(),
                " application/json-patch".to_string()
            ))
        );

        // Invalid input format.
        let input: [u8; 10] = [130, 140, 150, 130, 140, 150, 130, 140, 150, 160];
        assert_eq!(
            header.parse_header_line(&input[..]).unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::InvalidUtf8String(
                String::from_utf8(input.to_vec()).unwrap_err().utf8_error()
            ))
        );

        // Test valid transfer encoding.
        assert!(header
            .parse_header_line(b"Transfer-Encoding: chunked")
            .is_ok());
        assert!(header.chunked());

        // Test valid expect.
        assert!(header.parse_header_line(b"Expect: 100-continue").is_ok());
        assert!(header.expect());

        // Test valid media type.
        assert!(header
            .parse_header_line(b"Content-Type: application/json")
            .is_ok());

        // Test valid accept media type.
        assert!(header
            .parse_header_line(b"Accept: application/json")
            .is_ok());
        assert_eq!(header.accept, MediaType::ApplicationJson);
        assert!(header.parse_header_line(b"Accept: text/plain").is_ok());
        assert_eq!(header.accept, MediaType::PlainText);

        // Test invalid accept media type.
        assert!(header
            .parse_header_line(b"Accept: application/json-patch")
            .is_err());

        // Invalid content length.
        assert_eq!(
            header.parse_header_line(b"Content-Length: -1"),
            Err(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Content-Length".to_string(),
                " -1".to_string()
            )))
        );

        assert!(header
            .parse_header_line(b"Accept-Encoding: deflate")
            .is_ok());
        assert_eq!(
            header.parse_header_line(b"Accept-Encoding: compress, identity;q=0"),
            Err(RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Accept-Encoding".to_string(),
                " identity;q=0".to_string()
            )))
        );

        // Test custom header.
        assert_eq!(header.custom_entries().len(), 0);
        assert!(header.parse_header_line(b"Custom-Header: foo").is_ok());
        assert_eq!(
            header.custom_entries().get("Custom-Header").unwrap(),
            &"foo".to_string()
        );
        assert_eq!(header.custom_entries().len(), 1);
    }

    #[test]
    fn test_parse_header_whitespace() {
        let mut header = Headers::default();
        // Test that any number of whitespace characters are accepted before the header value.
        // For Content-Length
        assert!(header.parse_header_line(b"Content-Length:24").is_ok());
        assert!(header.parse_header_line(b"Content-Length:   24").is_ok());

        // For ContentType
        assert!(header
            .parse_header_line(b"Content-Type:application/json")
            .is_ok());
        assert!(header
            .parse_header_line(b"Content-Type:    application/json")
            .is_ok());

        // For Accept
        assert!(header.parse_header_line(b"Accept:application/json").is_ok());
        assert!(header
            .parse_header_line(b"Accept:  application/json")
            .is_ok());

        // For Transfer-Encoding
        assert!(header
            .parse_header_line(b"Transfer-Encoding:chunked")
            .is_ok());
        assert!(header.chunked());
        assert!(header
            .parse_header_line(b"Transfer-Encoding:    chunked")
            .is_ok());
        assert!(header.chunked());

        // For Server
        assert!(header.parse_header_line(b"Server:xxx.yyy.zzz").is_ok());
        assert!(header.parse_header_line(b"Server:   xxx.yyy.zzz").is_ok());

        // For Expect
        assert!(header.parse_header_line(b"Expect:100-continue").is_ok());
        assert!(header.parse_header_line(b"Expect:    100-continue").is_ok());

        // Test that custom headers' names and values are trimmed before being stored
        // inside the HashMap.
        assert!(header.parse_header_line(b"Foo:bar").is_ok());
        assert_eq!(header.custom_entries().get("Foo").unwrap(), "bar");
        assert!(header.parse_header_line(b"  Bar  :  foo  ").is_ok());
        assert_eq!(header.custom_entries().get("Bar").unwrap(), "foo");
    }

    #[test]
    fn test_header_try_from() {
        // Bad header.
        assert_eq!(
            Header::try_from(b"Encoding").unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::UnsupportedName("encoding".to_string()))
        );

        // Invalid encoding.
        let input: [u8; 10] = [130, 140, 150, 130, 140, 150, 130, 140, 150, 160];
        assert_eq!(
            Header::try_from(&input[..]).unwrap_err(),
            RequestError::InvalidRequest
        );

        // Test valid headers.
        let header = Header::try_from(b"Expect").unwrap();
        assert_eq!(header.raw(), b"Expect");

        let header = Header::try_from(b"Transfer-Encoding").unwrap();
        assert_eq!(header.raw(), b"Transfer-Encoding");

        let header = Header::try_from(b"content-length").unwrap();
        assert_eq!(header.raw(), b"Content-Length");

        let header = Header::try_from(b"Accept").unwrap();
        assert_eq!(header.raw(), b"Accept");
    }

    #[test]
    fn test_set_accept() {
        let mut headers = Headers::default();
        assert_eq!(headers.accept(), MediaType::PlainText);

        headers.set_accept(MediaType::ApplicationJson);
        assert_eq!(headers.accept(), MediaType::ApplicationJson);
    }
}
