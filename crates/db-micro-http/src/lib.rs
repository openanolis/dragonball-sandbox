// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
//! Minimal implementation of the [HTTP/1.0](https://tools.ietf.org/html/rfc1945)
//! and [HTTP/1.1](https://www.ietf.org/rfc/rfc2616.txt) protocols.
//!
//! HTTP/1.1 has a mandatory header **Host**, but as this crate is only used
//! for parsing API requests, this header (if present) is ignored.
//!
//! This HTTP implementation is stateless thus it does not support chunking or
//! compression.
//!
//! ## Supported Headers
//! The **micro_http** crate has support for parsing the following **Request**
//! headers:
//! - Content-Length
//! - Expect
//! - Transfer-Encoding
//!
//! The **Response** does not have a public interface for adding headers, but whenever
//! a write to the **Body** is made, the headers **ContentLength** and **MediaType**
//! are automatically updated.
//!
//! ### Media Types
//! The supported media types are:
//! - text/plain
//! - application/json
//!
//! ## Supported Methods
//! The supported HTTP Methods are:
//! - GET
//! - PUT
//! - PATCH
//!
//! ## Supported Status Codes
//! The supported status codes are:
//!
//! - Continue - 100
//! - OK - 200
//! - No Content - 204
//! - Bad Request - 400
//! - Not Found - 404
//! - Internal Server Error - 500
//! - Not Implemented - 501
//!
//! ## Example for parsing an HTTP Request from a slice
//! ```
//! use micro_http::{Request, Version};
//!
//! let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n\r\n";
//! let http_request = Request::try_from(request_bytes, None).unwrap();
//! assert_eq!(http_request.http_version(), Version::Http10);
//! assert_eq!(http_request.uri().get_abs_path(), "/home");
//! ```
//!
//! ## Example for creating an HTTP Response
//! ```
//! use micro_http::{Body, MediaType, Response, StatusCode, Version};
//!
//! let mut response = Response::new(Version::Http10, StatusCode::OK);
//! let body = String::from("This is a test");
//! response.set_body(Body::new(body.clone()));
//! response.set_content_type(MediaType::PlainText);
//!
//! assert!(response.status() == StatusCode::OK);
//! assert_eq!(response.body().unwrap(), Body::new(body));
//! assert_eq!(response.http_version(), Version::Http10);
//!
//! let mut response_buf: [u8; 126] = [0; 126];
//! assert!(response.write_all(&mut response_buf.as_mut()).is_ok());
//! ```
//!
//! `HttpConnection` can be used for automatic data exchange and parsing when
//! handling a client, but it only supports one stream.
//!
//! For handling multiple clients use `HttpServer`, which multiplexes `HttpConnection`s
//! and offers an easy to use interface. The server can run in either blocking or
//! non-blocking mode. Non-blocking is achieved by using `epoll` to make sure
//! `requests` will never block when called.
//!
//! ## Example for using the server
//!
//! ```
//! use micro_http::{HttpServer, Response, StatusCode};
//!
//! let path_to_socket = "/tmp/example.sock";
//! std::fs::remove_file(path_to_socket).unwrap_or_default();
//!
//! // Start the server.
//! let mut server = HttpServer::new(path_to_socket).unwrap();
//! server.start_server().unwrap();
//!
//! // Connect a client to the server so it doesn't block in our example.
//! let mut socket = std::os::unix::net::UnixStream::connect(path_to_socket).unwrap();
//!
//! // Server loop processing requests.
//! loop {
//!     for request in server.requests().unwrap() {
//!         let response = request.process(|request| {
//!             // Your code here.
//!             Response::new(request.http_version(), StatusCode::NoContent)
//!         });
//!         server.respond(response);
//!     }
//!     // Break this example loop.
//!     break;
//! }
//! ```

mod common;
mod connection;
mod request;
mod response;
mod router;
mod server;
use crate::common::ascii;
use crate::common::headers;

pub use self::router::{EndpointHandler, HttpRoutes, RouteError};
pub use crate::common::headers::{Encoding, Headers, MediaType};
pub use crate::common::{Body, HttpHeaderError, Method, Version};
pub use crate::connection::{ConnectionError, HttpConnection};
pub use crate::request::{Request, RequestError};
pub use crate::response::{Response, ResponseHeaders, StatusCode};
pub use crate::server::{HttpServer, ServerError, ServerRequest, ServerResponse};
