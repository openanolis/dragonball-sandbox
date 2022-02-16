// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::str::from_utf8;

use crate::common::ascii::{CR, CRLF_LEN, LF, SP};
pub use crate::common::HttpHeaderError;
pub use crate::common::RequestError;
use crate::common::{Body, Method, Version};
use crate::headers::Headers;

// This type represents the RequestLine raw parts: method, uri and version.
type RequestLineParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// Finds the first occurrence of `sequence` in the `bytes` slice.
///
/// Returns the starting position of the `sequence` in `bytes` or `None` if the
/// `sequence` is not found.
pub(crate) fn find(bytes: &[u8], sequence: &[u8]) -> Option<usize> {
    bytes
        .windows(sequence.len())
        .position(|window| window == sequence)
}

/// Wrapper over HTTP URIs.
///
/// The `Uri` can not be used directly and it is only accessible from an HTTP Request.
#[derive(Clone, Debug, PartialEq)]
pub struct Uri {
    string: String,
}

impl Uri {
    fn new(slice: &str) -> Self {
        Self {
            string: String::from(slice),
        }
    }

    fn try_from(bytes: &[u8]) -> Result<Self, RequestError> {
        if bytes.is_empty() {
            return Err(RequestError::InvalidUri("Empty URI not allowed."));
        }
        let utf8_slice =
            from_utf8(bytes).map_err(|_| RequestError::InvalidUri("Cannot parse URI as UTF-8."))?;
        Ok(Self::new(utf8_slice))
    }

    /// Returns the absolute path of the `Uri`.
    ///
    /// URIs can be represented in absolute form or relative form. The absolute form includes
    /// the HTTP scheme, followed by the absolute path as follows:
    /// "http:" "//" host [ ":" port ] [ abs_path ]
    /// The relative URIs can be one of net_path | abs_path | rel_path.
    /// This method only handles absolute URIs and relative URIs specified by abs_path.
    /// The abs_path is expected to start with '/'.
    ///
    /// # Errors
    /// Returns an empty byte array when the host or the path are empty/invalid.
    pub fn get_abs_path(&self) -> &str {
        const HTTP_SCHEME_PREFIX: &str = "http://";

        if self.string.starts_with(HTTP_SCHEME_PREFIX) {
            // Slice access is safe because we checked above that `self.string` size <= `HTTP_SCHEME_PREFIX.len()`.
            let without_scheme = &self.string[HTTP_SCHEME_PREFIX.len()..];
            if without_scheme.is_empty() {
                return "";
            }
            // The host in this case includes the port and contains the bytes after http:// up to
            // the next '/'.
            match without_scheme.bytes().position(|byte| byte == b'/') {
                // Slice access is safe because `position` validates that `len` is a valid index.
                Some(len) => &without_scheme[len..],
                None => "",
            }
        } else {
            if self.string.starts_with('/') {
                return self.string.as_str();
            }

            ""
        }
    }
}

/// Wrapper over an HTTP Request Line.
#[derive(Debug, PartialEq)]
pub struct RequestLine {
    method: Method,
    uri: Uri,
    http_version: Version,
}

impl RequestLine {
    fn parse_request_line(
        request_line: &[u8],
    ) -> std::result::Result<RequestLineParts, RequestError> {
        if let Some(method_end) = find(request_line, &[SP]) {
            // The slice access is safe because `find` validates that `method_end` < `request_line` size.
            let method = &request_line[..method_end];

            // `uri_start` <= `request_line` size.
            let uri_start = method_end.checked_add(1).ok_or(RequestError::Overflow)?;

            // Slice access is safe because `uri_start` <= `request_line` size.
            // If `uri_start` == `request_line` size, then `uri_and_version` will be an empty slice.
            let uri_and_version = &request_line[uri_start..];

            if let Some(uri_end) = find(uri_and_version, &[SP]) {
                // Slice access is safe because `find` validates that `uri_end` < `uri_and_version` size.
                let uri = &uri_and_version[..uri_end];

                // `version_start` <= `uri_and_version` size.
                let version_start = uri_end.checked_add(1).ok_or(RequestError::Overflow)?;

                // Slice access is safe because `version_start` <= `uri_and_version` size.
                let version = &uri_and_version[version_start..];

                return Ok((method, uri, version));
            }
        }

        // Request Line can be valid only if it contains the method, uri and version separated with SP.
        Err(RequestError::InvalidRequest)
    }

    /// Tries to parse a byte stream in a request line. Fails if the request line is malformed.
    ///
    /// # Errors
    /// `InvalidHttpMethod` is returned if the specified HTTP method is unsupported.
    /// `InvalidHttpVersion` is returned if the specified HTTP version is unsupported.
    /// `InvalidUri` is returned if the specified Uri is not valid.
    pub fn try_from(request_line: &[u8]) -> Result<Self, RequestError> {
        let (method, uri, version) = Self::parse_request_line(request_line)?;

        Ok(Self {
            method: Method::try_from(method)?,
            uri: Uri::try_from(uri)?,
            http_version: Version::try_from(version)?,
        })
    }

    // Returns the minimum length of a valid request. The request must contain
    // the method (GET), the URI (minimum 1 character), the HTTP version(HTTP/DIGIT.DIGIT) and
    // 2 separators (SP).
    fn min_len() -> usize {
        // Addition is safe because these are small constants.
        Method::Get.raw().len() + 1 + Version::Http10.raw().len() + 2
    }
}

/// Wrapper over an HTTP Request.
#[derive(Debug)]
pub struct Request {
    /// The request line of the request.
    pub request_line: RequestLine,
    /// The headers of the request.
    pub headers: Headers,
    /// The body of the request.
    pub body: Option<Body>,
    /// The optional files associated with the request.
    pub files: Vec<File>,
}

impl Request {
    /// Parses a byte slice into a HTTP Request.
    ///
    /// The byte slice is expected to have the following format: </br>
    ///     * Request Line: "GET SP Request-uri SP HTTP/1.0 CRLF" - Mandatory </br>
    ///     * Request Headers "<headers> CRLF"- Optional </br>
    ///     * Empty Line "CRLF" </br>
    ///     * Entity Body - Optional </br>
    /// The request headers and the entity body are not parsed and None is returned because
    /// these are not used by the MMDS server.
    /// The only supported method is GET and the HTTP protocol is expected to be HTTP/1.0
    /// or HTTP/1.1.
    ///
    /// # Errors
    /// The function returns InvalidRequest when parsing the byte stream fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use micro_http::Request;
    ///
    /// let max_request_len = 2000;
    /// let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n\r\n";
    /// let http_request = Request::try_from(request_bytes, Some(max_request_len)).unwrap();
    /// ```
    pub fn try_from(byte_stream: &[u8], max_len: Option<usize>) -> Result<Self, RequestError> {
        // If a size limit is provided, verify the request length does not exceed it.
        if let Some(limit) = max_len {
            if byte_stream.len() >= limit {
                return Err(RequestError::InvalidRequest);
            }
        }

        // The first line of the request is the Request Line. The line ending is CR LF.
        let request_line_end = match find(byte_stream, &[CR, LF]) {
            Some(len) => len,
            // If no CR LF is found in the stream, the request format is invalid.
            None => return Err(RequestError::InvalidRequest),
        };

        // Slice access is safe because `find` validates that `request_line_end` < `byte_stream` size.
        let request_line_bytes = &byte_stream[..request_line_end];
        if request_line_bytes.len() < RequestLine::min_len() {
            return Err(RequestError::InvalidRequest);
        }

        let request_line = RequestLine::try_from(request_line_bytes)?;

        // Find the next CR LF CR LF sequence in our buffer starting at the end on the Request
        // Line, including the trailing CR LF previously found.
        match find(&byte_stream[request_line_end..], &[CR, LF, CR, LF]) {
            // If we have found a CR LF CR LF at the end of the Request Line, the request
            // is complete.
            Some(0) => Ok(Self {
                request_line,
                headers: Headers::default(),
                body: None,
                files: Vec::new(),
            }),
            Some(headers_end) => {
                // Parse the request headers.
                // Start by removing the leading CR LF from them.
                // The addition is safe because `find()` guarantees that `request_line_end`
                // precedes 2 `CRLF` sequences.
                let headers_start = request_line_end + CRLF_LEN;
                // Slice access is safe because starting from `request_line_end` there are at least two CRLF
                // (enforced by `find` at the start of this method).
                let headers_and_body = &byte_stream[headers_start..];
                // Because we advanced the start with CRLF_LEN, we now have to subtract CRLF_LEN
                // from the end in order to keep the same window.
                // Underflow is not possible here because `byte_stream[request_line_end..]` starts with CR LF,
                // so `headers_end` can be either zero (this case is treated separately in the first match arm)
                // or >= 3 (current case).
                let headers_end = headers_end - CRLF_LEN;
                // Slice access is safe because `headers_end` is checked above
                // (`find` gives a valid position, and  subtracting 2 can't underflow).
                let headers = Headers::try_from(&headers_and_body[..headers_end])?;

                // Parse the body of the request.
                // Firstly check if we have a body.
                let body = match headers.content_length() {
                    0 => {
                        // No request body.
                        None
                    }
                    content_length => {
                        if request_line.method == Method::Get {
                            return Err(RequestError::InvalidRequest);
                        }
                        // Multiplication is safe because `CRLF_LEN` is a small constant.
                        // Addition is also safe because `headers_end` started out as the result
                        // of `find(<something>, CRLFCRLF)`, then `CRLF_LEN` was subtracted from it.
                        let crlf_end = headers_end + 2 * CRLF_LEN;
                        // This can't underflow because `headers_and_body.len()` >= `crlf_end`.
                        let body_len = headers_and_body.len() - crlf_end;
                        // Headers suggest we have a body, but the buffer is shorter than the specified
                        // content length.
                        if body_len < content_length as usize {
                            return Err(RequestError::InvalidRequest);
                        }
                        // Slice access is safe because `crlf_end` is the index after two CRLF
                        // (it is <= `headers_and_body` size).
                        let body_as_bytes = &headers_and_body[crlf_end..];
                        // If the actual length of the body is different than the `Content-Length` value
                        // in the headers, then this request is invalid.
                        if body_as_bytes.len() == content_length as usize {
                            Some(Body::new(body_as_bytes))
                        } else {
                            return Err(RequestError::InvalidRequest);
                        }
                    }
                };

                Ok(Self {
                    request_line,
                    headers,
                    body,
                    files: Vec::new(),
                })
            }
            // If we can't find a CR LF CR LF even though the request should have headers
            // the request format is invalid.
            None => Err(RequestError::InvalidRequest),
        }
    }

    /// Returns the `Uri` from the parsed `Request`.
    ///
    /// The return value can be used to get the absolute path of the URI.
    pub fn uri(&self) -> &Uri {
        &self.request_line.uri
    }

    /// Returns the HTTP `Version` of the `Request`.
    pub fn http_version(&self) -> Version {
        self.request_line.http_version
    }

    /// Returns the HTTP `Method` of the `Request`.
    pub fn method(&self) -> Method {
        self.request_line.method
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl PartialEq for Request {
        fn eq(&self, other: &Self) -> bool {
            // Ignore the other fields of Request for now because they are not used.
            self.request_line == other.request_line
                && self.headers.content_length() == other.headers.content_length()
                && self.headers.expect() == other.headers.expect()
                && self.headers.chunked() == other.headers.chunked()
        }
    }

    impl RequestLine {
        pub fn new(method: Method, uri: &str, http_version: Version) -> Self {
            Self {
                method,
                uri: Uri::new(uri),
                http_version,
            }
        }
    }

    #[test]
    fn test_uri() {
        for tc in &vec![
            ("http://localhost/home", "/home"),
            ("http://localhost:8080/home", "/home"),
            ("http://localhost/home/sub", "/home/sub"),
            ("/home", "/home"),
            ("home", ""),
            ("http://", ""),
            ("http://192.168.0.0", ""),
        ] {
            assert_eq!(Uri::new(tc.0).get_abs_path(), tc.1);
        }
    }

    #[test]
    fn test_find() {
        let bytes: &[u8; 13] = b"abcacrgbabsjl";

        for tc in &vec![
            ("ac", Some(3)),
            ("rgb", Some(5)),
            ("ab", Some(0)),
            ("l", Some(12)),
            ("abcacrgbabsjl", Some(0)),
            ("jle", None),
            ("asdkjhasjhdjhgsadg", None),
        ] {
            assert_eq!(find(&bytes[..], tc.0.as_bytes()), tc.1);
        }
    }

    #[test]
    fn test_into_request_line() {
        let expected_request_line = RequestLine {
            http_version: Version::Http10,
            method: Method::Get,
            uri: Uri::new("http://localhost/home"),
        };

        let request_line = b"GET http://localhost/home HTTP/1.0";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap(),
            expected_request_line
        );

        let expected_request_line = RequestLine {
            http_version: Version::Http11,
            method: Method::Get,
            uri: Uri::new("http://localhost/home"),
        };

        // Happy case with request line ending in CRLF.
        let request_line = b"GET http://localhost/home HTTP/1.1";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap(),
            expected_request_line
        );

        // Happy case with request line ending in LF instead of CRLF.
        let request_line = b"GET http://localhost/home HTTP/1.1";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap(),
            expected_request_line
        );

        // Test for invalid request missing the separator.
        let request_line = b"GET";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidRequest
        );

        // Test for invalid method.
        let request_line = b"POST http://localhost/home HTTP/1.0";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidHttpMethod("Unsupported HTTP method.")
        );

        // Test for invalid uri.
        let request_line = b"GET  HTTP/1.0";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidUri("Empty URI not allowed.")
        );

        // Test for invalid HTTP version.
        let request_line = b"GET http://localhost/home HTTP/2.0";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidHttpVersion("Unsupported HTTP version.")
        );

        // Test for invalid format with no method, uri or version.
        let request_line = b"nothing";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidRequest
        );

        // Test for invalid format with no version.
        let request_line = b"GET /";
        assert_eq!(
            RequestLine::try_from(request_line).unwrap_err(),
            RequestError::InvalidRequest
        );
    }

    #[test]
    fn test_into_request() {
        let expected_request = Request {
            request_line: RequestLine {
                http_version: Version::Http10,
                method: Method::Get,
                uri: Uri::new("http://localhost/home"),
            },
            body: None,
            files: Vec::new(),
            headers: Headers::default(),
        };
        let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n\
                                     Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        assert_eq!(request, expected_request);
        assert_eq!(request.uri(), &Uri::new("http://localhost/home"));
        assert_eq!(request.http_version(), Version::Http10);
        assert!(request.body.is_none());

        // Test for invalid Request (missing CR LF).
        let request_bytes = b"GET / HTTP/1.1";
        assert_eq!(
            Request::try_from(request_bytes, None).unwrap_err(),
            RequestError::InvalidRequest
        );

        // Test for invalid Request (length is less than minimum).
        let request_bytes = b"GET";
        assert_eq!(
            Request::try_from(request_bytes, None).unwrap_err(),
            RequestError::InvalidRequest
        );

        // Test for invalid Request (`GET` requests should have no body).
        let request_bytes = b"GET /machine-config HTTP/1.1\r\n\
                                        Content-Length: 13\r\n\
                                        Content-Type: application/json\r\n\r\nwhatever body";
        assert_eq!(
            Request::try_from(request_bytes, None).unwrap_err(),
            RequestError::InvalidRequest
        );

        // Test for request larger than maximum len provided.
        let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n\
                                     Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\n\r\n";
        assert_eq!(
            Request::try_from(request_bytes, Some(20)).unwrap_err(),
            RequestError::InvalidRequest
        );

        // Test request smaller than maximum len provided is ok.
        let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n\
                                     Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\n\r\n";
        assert!(Request::try_from(request_bytes, Some(500)).is_ok());

        // Test for a request with the headers we are looking for.
        let request_bytes = b"PATCH http://localhost/home HTTP/1.1\r\n\
                              Expect: 100-continue\r\n\
                              Transfer-Encoding: chunked\r\n\
                              Content-Length: 26\r\n\r\nthis is not\n\r\na json \nbody";
        let request = Request::try_from(request_bytes, None).unwrap();
        assert_eq!(request.uri(), &Uri::new("http://localhost/home"));
        assert_eq!(request.http_version(), Version::Http11);
        assert_eq!(request.method(), Method::Patch);
        assert!(request.headers.chunked());
        assert!(request.headers.expect());
        assert_eq!(request.headers.content_length(), 26);
        assert_eq!(
            request.body.unwrap().body,
            String::from("this is not\n\r\na json \nbody")
                .as_bytes()
                .to_vec()
        );

        // Test for an invalid request format.
        Request::try_from(b"PATCH http://localhost/home HTTP/1.1\r\n", None).unwrap_err();

        // Test for an invalid encoding.
        let request_bytes = b"PATCH http://localhost/home HTTP/1.1\r\n\
                                Expect: 100-continue\r\n\
                                Transfer-Encoding: identity; q=0\r\n\
                                Content-Length: 26\r\n\r\nthis is not\n\r\na json \nbody";

        assert!(Request::try_from(request_bytes, None).is_ok());

        // Test for an invalid content length.
        let request_bytes = b"PATCH http://localhost/home HTTP/1.1\r\n\
                                Content-Length: 5000\r\n\r\nthis is a short body";
        let request = Request::try_from(request_bytes, None).unwrap_err();
        assert_eq!(request, RequestError::InvalidRequest);

        // Test for a request without a body and an optional header.
        let request_bytes = b"GET http://localhost/ HTTP/1.0\r\n\
                                Accept-Encoding: gzip\r\n\r\n";
        let request = Request::try_from(request_bytes, None).unwrap();
        assert_eq!(request.uri(), &Uri::new("http://localhost/"));
        assert_eq!(request.http_version(), Version::Http10);
        assert_eq!(request.method(), Method::Get);
        assert!(!request.headers.chunked());
        assert!(!request.headers.expect());
        assert_eq!(request.headers.content_length(), 0);
        assert!(request.body.is_none());

        let request_bytes = b"GET http://localhost/ HTTP/1.0\r\n\
                                Accept-Encoding: identity;q=0\r\n\r\n";
        let request = Request::try_from(request_bytes, None);
        assert_eq!(
            request.unwrap_err(),
            RequestError::HeaderError(HttpHeaderError::InvalidValue(
                "Accept-Encoding".to_string(),
                "identity;q=0".to_string()
            ))
        );
    }
}
