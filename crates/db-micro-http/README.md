# db-micro-http

## Design

db-micro-http is a minimal implementations of HTTP 1.0 and HTTP 1.1 protocols. 

## Acknowledgement

This crate is forked from the [Firecracker](https://github.com/firecracker-microvm/firecracker) project with modification to support more usage cases.

## Example

Example for parsing an HTTP Request from a slice:

```rust
use micro_http::{Request, Version};
let request_bytes = b"GET http://localhost/home HTTP/1.0\r\n\r\n";
let http_request = Request::try_from(request_bytes, None).unwrap();
assert_eq!(http_request.http_version(), Version::Http10);
assert_eq!(http_request.uri().get_abs_path(), "/home");
```

Example for creating an HTTP Response:

```rust
use micro_http::{Body, MediaType, Response, StatusCode, Version};
let mut response = Response::new(Version::Http10, StatusCode::OK);
let body = String::from("This is a test");
response.set_body(Body::new(body.clone()));
response.set_content_type(MediaType::PlainText);

assert!(response.status() == StatusCode::OK);
assert_eq!(response.body().unwrap(), Body::new(body));
assert_eq!(response.http_version(), Version::Http10);

let mut response_buf: [u8; 126] = [0; 126];
assert!(response.write_all(&mut response_buf.as_mut()).is_ok());
```

Example for using the server:

```rust
use micro_http::{HttpServer, Response, StatusCode};

let path_to_socket = "/tmp/example.sock";
std::fs::remove_file(path_to_socket).unwrap_or_default();
// Start the server.
let mut server = HttpServer::new(path_to_socket).unwrap();
server.start_server().unwrap();

// Connect a client to the server so it doesn't block in our example.
let mut socket = std::os::unix::net::UnixStream::connect(path_to_socket).unwrap();

// Server loop processing requests.
loop {
    for request in server.requests().unwrap() {
        let response = request.process(|request| {
            // Your code here.
            Response::new(request.http_version(), StatusCode::NoContent)
        });
        server.respond(response);
    }
    // Break this example loop.
    break;
}
```

