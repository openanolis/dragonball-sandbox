// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use crate::common::{Body, Version};
pub use crate::common::{ConnectionError, RequestError, ServerError};
use crate::connection::HttpConnection;
use crate::request::Request;
use crate::response::{Response, StatusCode};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use vmm_sys_util::epoll;

static SERVER_FULL_ERROR_MESSAGE: &[u8] = b"HTTP/1.1 503\r\n\
                                            Server: Firecracker API\r\n\
                                            Connection: close\r\n\
                                            Content-Length: 40\r\n\r\n{ \"error\": \"Too many open connections\" }";
const MAX_CONNECTIONS: usize = 10;
/// Payload max size
pub(crate) const MAX_PAYLOAD_SIZE: usize = 51200;

type Result<T> = std::result::Result<T, ServerError>;

/// Wrapper over `Request` which adds an identification token.
pub struct ServerRequest {
    /// Inner request.
    pub request: Request,
    /// Identification token.
    id: u64,
}

impl ServerRequest {
    /// Creates a new `ServerRequest` object from an existing `Request`,
    /// adding an identification token.
    pub fn new(request: Request, id: u64) -> Self {
        Self { request, id }
    }

    /// Returns a reference to the inner request.
    pub fn inner(&self) -> &Request {
        &self.request
    }

    /// Calls the function provided on the inner request to obtain the response.
    /// The response is then wrapped in a `ServerResponse`.
    ///
    /// Returns a `ServerResponse` ready for yielding to the server
    pub fn process<F>(&self, mut callable: F) -> ServerResponse
    where
        F: FnMut(&Request) -> Response,
    {
        let http_response = callable(self.inner());
        ServerResponse::new(http_response, self.id)
    }
}

/// Wrapper over `Response` which adds an identification token.
pub struct ServerResponse {
    /// Inner response.
    response: Response,
    /// Identification token.
    id: u64,
}

impl ServerResponse {
    fn new(response: Response, id: u64) -> Self {
        Self { response, id }
    }
}

/// Describes the state of the connection as far as data exchange
/// on the stream is concerned.
#[derive(PartialOrd, PartialEq)]
enum ClientConnectionState {
    AwaitingIncoming,
    AwaitingOutgoing,
    Closed,
}

/// Wrapper over `HttpConnection` which keeps track of yielded
/// requests and absorbed responses.
struct ClientConnection<T> {
    /// The `HttpConnection` object which handles data exchange.
    connection: HttpConnection<T>,
    /// The state of the connection in the `epoll` structure.
    state: ClientConnectionState,
    /// Represents the difference between yielded requests and
    /// absorbed responses.
    /// This has to be `0` if we want to drop the connection.
    in_flight_response_count: u32,
}

impl<T: Read + Write + ScmSocket> ClientConnection<T> {
    fn new(connection: HttpConnection<T>) -> Self {
        Self {
            connection,
            state: ClientConnectionState::AwaitingIncoming,
            in_flight_response_count: 0,
        }
    }

    fn read(&mut self) -> Result<Vec<Request>> {
        // Data came into the connection.
        let mut parsed_requests = vec![];
        match self.connection.try_read() {
            Err(ConnectionError::ConnectionClosed) => {
                // Connection timeout.
                self.state = ClientConnectionState::Closed;
                // We don't want to propagate this to the server and we will
                // return no requests and wait for the connection to become
                // safe to drop.
                return Ok(vec![]);
            }
            Err(ConnectionError::StreamReadError(inner)) => {
                // Reading from the connection failed.
                // We should try to write an error message regardless.
                let mut internal_error_response =
                    Response::new(Version::Http11, StatusCode::InternalServerError);
                internal_error_response.set_body(Body::new(inner.to_string()));
                self.connection.enqueue_response(internal_error_response);
            }
            Err(ConnectionError::ParseError(inner)) => {
                // An error occurred while parsing the read bytes.
                // Check if there are any valid parsed requests in the queue.
                while let Some(_discarded_request) = self.connection.pop_parsed_request() {}

                // Send an error response for the request that gave us the error.
                let mut error_response = Response::new(Version::Http11, StatusCode::BadRequest);
                error_response.set_body(Body::new(format!(
                    "{{ \"error\": \"{}\nAll previous unanswered requests will be dropped.\" }}",
                    inner
                )));
                self.connection.enqueue_response(error_response);
            }
            Err(ConnectionError::InvalidWrite) | Err(ConnectionError::StreamWriteError(_)) => {
                // This is unreachable because `HttpConnection::try_read()` cannot return this error variant.
                unreachable!();
            }
            Ok(()) => {
                while let Some(request) = self.connection.pop_parsed_request() {
                    // Add all valid requests to `parsed_requests`.
                    parsed_requests.push(request);
                }
            }
        }
        self.in_flight_response_count = self
            .in_flight_response_count
            .checked_add(parsed_requests.len() as u32)
            .ok_or(ServerError::Overflow)?;
        // If the state of the connection has changed, we need to update
        // the event set in the `epoll` structure.
        if self.connection.pending_write() {
            self.state = ClientConnectionState::AwaitingOutgoing;
        }

        Ok(parsed_requests)
    }

    fn write(&mut self) -> Result<()> {
        // The stream is available for writing.
        match self.connection.try_write() {
            Err(ConnectionError::ConnectionClosed) | Err(ConnectionError::StreamWriteError(_)) => {
                // Writing to the stream failed so it will be removed.
                self.state = ClientConnectionState::Closed;
            }
            Err(ConnectionError::InvalidWrite) => {
                // A `try_write` call was performed on a connection that has nothing
                // to write.
                return Err(ServerError::ConnectionError(ConnectionError::InvalidWrite));
            }
            _ => {
                // Check if we still have bytes to write for this connection.
                if !self.connection.pending_write() {
                    self.state = ClientConnectionState::AwaitingIncoming;
                }
            }
        }
        Ok(())
    }

    fn enqueue_response(&mut self, response: Response) -> Result<()> {
        if self.state != ClientConnectionState::Closed {
            self.connection.enqueue_response(response);
        }
        self.in_flight_response_count = self
            .in_flight_response_count
            .checked_sub(1)
            .ok_or(ServerError::Underflow)?;
        Ok(())
    }

    /// Discards all pending writes from the inner connection.
    fn clear_write_buffer(&mut self) {
        self.connection.clear_write_buffer();
    }

    // Returns `true` if the connection is closed and safe to drop.
    fn is_done(&self) -> bool {
        self.state == ClientConnectionState::Closed
            && !self.connection.pending_write()
            && self.in_flight_response_count == 0
    }
}

/// HTTP Server implementation using Unix Domain Sockets and `EPOLL` to
/// handle multiple connections on the same thread.
///
/// The function that handles incoming connections, parses incoming
/// requests and sends responses for awaiting requests is `requests`.
/// It can be called in a loop, which will render the thread that the
/// server runs on incapable of performing other operations, or it can
/// be used in another `EPOLL` structure, as it provides its `epoll`,
/// which is a wrapper over the file descriptor of the epoll structure
/// used within the server, and it can be added to another one using
/// the `EPOLLIN` flag. Whenever there is a notification on that fd,
/// `requests` should be called once.
///
/// # Example
///
/// ## Starting and running the server
///
/// ```
/// use micro_http::{HttpServer, Response, StatusCode};
///
/// let path_to_socket = "/tmp/example.sock";
/// std::fs::remove_file(path_to_socket).unwrap_or_default();
///
/// // Start the server.
/// let mut server = HttpServer::new(path_to_socket).unwrap();
/// server.start_server().unwrap();
///
/// // Connect a client to the server so it doesn't block in our example.
/// let mut socket = std::os::unix::net::UnixStream::connect(path_to_socket).unwrap();
///
/// // Server loop processing requests.
/// loop {
///     for request in server.requests().unwrap() {
///         let response = request.process(|request| {
///             // Your code here.
///             Response::new(request.http_version(), StatusCode::NoContent)
///         });
///         server.respond(response);
///     }
///     // Break this example loop.
///     break;
/// }
/// ```
pub struct HttpServer {
    /// Socket on which we listen for new connections.
    socket: UnixListener,
    /// Server's epoll instance.
    epoll: epoll::Epoll,
    /// Holds the token-connection pairs of the server.
    /// Each connection has an associated identification token, which is
    /// the file descriptor of the underlying stream.
    /// We use the file descriptor of the stream as the key for mapping
    /// connections because the 1-to-1 relation is guaranteed by the OS.
    connections: HashMap<RawFd, ClientConnection<UnixStream>>,
    /// Payload max size
    payload_max_size: usize,
}

impl HttpServer {
    /// Constructor for `HttpServer`.
    ///
    /// Returns the newly formed `HttpServer`.
    ///
    /// # Errors
    /// Returns an `IOError` when binding or `epoll::create` fails.
    pub fn new<P: AsRef<Path>>(path_to_socket: P) -> Result<Self> {
        let socket = UnixListener::bind(path_to_socket).map_err(ServerError::IOError)?;
        let epoll = epoll::Epoll::new().map_err(ServerError::IOError)?;
        Ok(Self {
            socket,
            epoll,
            connections: HashMap::new(),
            payload_max_size: MAX_PAYLOAD_SIZE,
        })
    }

    /// Constructor for `HttpServer`.
    ///
    /// Note that this function requires the socket_fd to be solely owned
    /// and not be associated with another File in the caller as it uses
    /// the unsafe `UnixListener::from_raw_fd method`.
    ///
    /// Returns the newly formed `HttpServer`.
    ///
    /// # Errors
    /// Returns an `IOError` when `epoll::create` fails.
    pub fn new_from_fd(socket_fd: RawFd) -> Result<Self> {
        let socket = unsafe { UnixListener::from_raw_fd(socket_fd) };
        let epoll = epoll::Epoll::new().map_err(ServerError::IOError)?;
        Ok(HttpServer {
            socket,
            epoll,
            connections: HashMap::new(),
            payload_max_size: MAX_PAYLOAD_SIZE,
        })
    }

    /// This function sets the limit for PUT/PATCH requests. It overwrites the
    /// default limit of 0.05MiB with the one allowed by server.
    pub fn set_payload_max_size(&mut self, request_payload_max_size: usize) {
        self.payload_max_size = request_payload_max_size;
    }

    /// Starts the HTTP Server.
    pub fn start_server(&mut self) -> Result<()> {
        // Add the socket on which we listen for new connections to the
        // `epoll` structure.
        Self::epoll_add(&self.epoll, self.socket.as_raw_fd())
    }

    /// This function is responsible for the data exchange with the clients and should
    /// be called when we are either notified through `epoll` that we need to exchange
    /// data with at least a client or when we don't need to perform any other operations
    /// on this thread and we can afford to call it in a loop.
    ///
    /// Note that this function will block the current thread if there are no notifications
    /// to be handled by the server.
    ///
    /// Returns a collection of complete and valid requests to be processed by the user
    /// of the server. Once processed, responses should be sent using `enqueue_responses()`.
    ///
    /// # Errors
    /// `IOError` is returned when `read`, `write` or `epoll::ctl` operations fail.
    /// `ServerFull` is returned when a client is trying to connect to the server, but
    /// full capacity has already been reached.
    /// `InvalidWrite` is returned when the server attempted to perform a write operation
    /// on a connection on which it is not possible.
    pub fn requests(&mut self) -> Result<Vec<ServerRequest>> {
        let mut parsed_requests: Vec<ServerRequest> = vec![];
        let mut events = vec![epoll::EpollEvent::default(); MAX_CONNECTIONS];
        // This is a wrapper over the syscall `epoll_wait` and it will block the
        // current thread until at least one event is received.
        // The received notifications will then populate the `events` array with
        // `event_count` elements, where 1 <= event_count <= MAX_CONNECTIONS.
        let event_count = match self.epoll.wait(-1, &mut events[..]) {
            Ok(event_count) => event_count,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => 0,
            Err(e) => return Err(ServerError::IOError(e)),
        };
        // We use `take()` on the iterator over `events` as, even though only
        // `events_count` events have been inserted into `events`, the size of
        // the array is still `MAX_CONNECTIONS`, so we discard empty elements
        // at the end of the array.
        for e in events.iter().take(event_count) {
            // Check the file descriptor which produced the notification `e`.
            // It could be that we have a new connection, or one of our open
            // connections is ready to exchange data with a client.
            if e.fd() == self.socket.as_raw_fd() {
                // We have received a notification on the listener socket, which
                // means we have a new connection to accept.
                match self.handle_new_connection() {
                    // If the server is full, we send a message to the client
                    // notifying them that we will close the connection, then
                    // we discard it.
                    Err(ServerError::ServerFull) => {
                        self.socket
                            .accept()
                            .map_err(ServerError::IOError)
                            .and_then(move |(mut stream, _)| {
                                stream
                                    .write(SERVER_FULL_ERROR_MESSAGE)
                                    .map_err(ServerError::IOError)
                            })?;
                    }
                    // An internal error will compromise any in-flight requests.
                    Err(error) => return Err(error),
                    Ok(()) => {}
                };
            } else {
                // We have a notification on one of our open connections.
                let fd = e.fd();
                let client_connection = self.connections.get_mut(&fd).unwrap();

                // If we receive a hang up on a connection, we clear the write buffer and set
                // the connection state to closed to mark it ready for removal from the
                // connections map, which will gracefully close the socket.
                // The connection is also marked for removal when encountering `EPOLLERR`,
                // since this is an "error condition happened on the associated file
                // descriptor", according to the `epoll_ctl` man page.
                if e.event_set().contains(epoll::EventSet::ERROR)
                    || e.event_set().contains(epoll::EventSet::HANG_UP)
                    || e.event_set().contains(epoll::EventSet::READ_HANG_UP)
                {
                    client_connection.clear_write_buffer();
                    client_connection.state = ClientConnectionState::Closed;
                    continue;
                }

                if e.event_set().contains(epoll::EventSet::IN) {
                    // We have bytes to read from this connection.
                    // If our `read` yields `Request` objects, we wrap them with an ID before
                    // handing them to the user.
                    parsed_requests.append(
                        &mut client_connection
                            .read()?
                            .into_iter()
                            .map(|request| ServerRequest::new(request, e.data()))
                            .collect(),
                    );
                    // If the connection was incoming before we read and we now have to write
                    // either an error message or an `expect` response, we change its `epoll`
                    // event set to notify us when the stream is ready for writing.
                    if client_connection.state == ClientConnectionState::AwaitingOutgoing {
                        Self::epoll_mod(
                            &self.epoll,
                            fd,
                            epoll::EventSet::OUT | epoll::EventSet::READ_HANG_UP,
                        )?;
                    }
                } else if e.event_set().contains(epoll::EventSet::OUT) {
                    // We have bytes to write on this connection.
                    client_connection.write()?;
                    // If the connection was outgoing before we tried to write the responses
                    // and we don't have any more responses to write, we change the `epoll`
                    // event set to notify us when we have bytes to read from the stream.
                    if client_connection.state == ClientConnectionState::AwaitingIncoming {
                        Self::epoll_mod(
                            &self.epoll,
                            fd,
                            epoll::EventSet::IN | epoll::EventSet::READ_HANG_UP,
                        )?;
                    }
                }
            }
        }

        // Remove dead connections.
        let epoll = &self.epoll;
        self.connections.retain(|rawfd, client_connection| {
            if client_connection.is_done() {
                // The rawfd should have been registered to the epoll fd.
                Self::epoll_del(epoll, *rawfd).unwrap();
                false
            } else {
                true
            }
        });

        Ok(parsed_requests)
    }

    /// This function is responsible with flushing any remaining outgoing
    /// requests on the server.
    ///
    /// Note that this function can block the thread on write, since the
    /// operation is blocking.
    pub fn flush_outgoing_writes(&mut self) {
        for (_, connection) in self.connections.iter_mut() {
            while connection.state == ClientConnectionState::AwaitingOutgoing {
                if let Err(e) = connection.write() {
                    if let ServerError::ConnectionError(ConnectionError::InvalidWrite) = e {
                        // Nothing is logged since an InvalidWrite means we have successfully
                        // flushed the connection
                    }
                    break;
                }
            }
        }
    }

    /// The file descriptor of the `epoll` structure can enable the server to become
    /// a non-blocking structure in an application.
    ///
    /// Returns a reference to the instance of the server's internal `epoll` structure.
    ///
    /// # Example
    ///
    /// ## Non-blocking server
    /// ```
    /// use std::os::unix::io::AsRawFd;
    ///
    /// use micro_http::{HttpServer, Response, StatusCode};
    /// use vmm_sys_util::epoll;
    ///
    /// // Create our epoll manager.
    /// let epoll = epoll::Epoll::new().unwrap();
    ///
    /// let path_to_socket = "/tmp/epoll_example.sock";
    /// std::fs::remove_file(path_to_socket).unwrap_or_default();
    ///
    /// // Start the server.
    /// let mut server = HttpServer::new(path_to_socket).unwrap();
    /// server.start_server().unwrap();
    ///
    /// // Add our server to the `epoll` manager.
    /// epoll.ctl(
    ///     epoll::ControlOperation::Add,
    ///     server.epoll().as_raw_fd(),
    ///     epoll::EpollEvent::new(epoll::EventSet::IN, 1234u64),
    /// )
    /// .unwrap();
    ///
    /// // Connect a client to the server so it doesn't block in our example.
    /// let mut socket = std::os::unix::net::UnixStream::connect(path_to_socket).unwrap();
    ///
    /// // Control loop of the application.
    /// let mut events = Vec::with_capacity(10);
    /// loop {
    ///     let num_ev = epoll.wait(-1, events.as_mut_slice());
    ///     for event in events {
    ///         match event.data() {
    ///             // The server notification.
    ///             1234 => {
    ///                 let request = server.requests();
    ///                 // Process...
    ///             }
    ///             // Other `epoll` notifications.
    ///             _ => {
    ///                 // Do other computation.
    ///             }
    ///         }
    ///     }
    ///     // Break this example loop.
    ///     break;
    /// }
    /// ```
    pub fn epoll(&self) -> &epoll::Epoll {
        &self.epoll
    }

    /// Enqueues the provided responses in the outgoing connection.
    ///
    /// # Errors
    /// `IOError` is returned when an `epoll::ctl` operation fails.
    pub fn enqueue_responses(&mut self, responses: Vec<ServerResponse>) -> Result<()> {
        for response in responses {
            self.respond(response)?;
        }

        Ok(())
    }

    /// Adds the provided response to the outgoing buffer in the corresponding connection.
    ///
    /// # Errors
    /// `IOError` is returned when an `epoll::ctl` operation fails.
    /// `Underflow` is returned when `enqueue_response` fails.
    pub fn respond(&mut self, response: ServerResponse) -> Result<()> {
        if let Some(client_connection) = self.connections.get_mut(&(response.id as i32)) {
            // If the connection was incoming before we enqueue the response, we change its
            // `epoll` event set to notify us when the stream is ready for writing.
            if let ClientConnectionState::AwaitingIncoming = client_connection.state {
                client_connection.state = ClientConnectionState::AwaitingOutgoing;
                Self::epoll_mod(
                    &self.epoll,
                    response.id as RawFd,
                    epoll::EventSet::OUT | epoll::EventSet::READ_HANG_UP,
                )?;
            }
            client_connection.enqueue_response(response.response)?;
        }
        Ok(())
    }

    /// Accepts a new incoming connection and adds it to the `epoll` notification structure.
    ///
    /// # Errors
    /// `IOError` is returned when socket or epoll operations fail.
    /// `ServerFull` is returned if server full capacity has been reached.
    fn handle_new_connection(&mut self) -> Result<()> {
        if self.connections.len() == MAX_CONNECTIONS {
            // If we want a replacement policy for connections
            // this is where we will have it.
            return Err(ServerError::ServerFull);
        }

        self.socket
            .accept()
            .map_err(ServerError::IOError)
            .and_then(|(stream, _)| {
                // `HttpConnection` is supposed to work with non-blocking streams.
                stream
                    .set_nonblocking(true)
                    .map(|_| stream)
                    .map_err(ServerError::IOError)
            })
            .and_then(|stream| {
                // Add the stream to the `epoll` structure and listen for bytes to be read.
                let raw_fd = stream.as_raw_fd();
                Self::epoll_add(&self.epoll, raw_fd)?;
                let mut conn = HttpConnection::new(stream);
                conn.set_payload_max_size(self.payload_max_size);
                // Then add it to our open connections.
                self.connections.insert(raw_fd, ClientConnection::new(conn));
                Ok(())
            })
    }

    /// Changes the event type for a connection to either listen for incoming bytes
    /// or for when the stream is ready for writing.
    ///
    /// # Errors
    /// `IOError` is returned when an `EPOLL_CTL_MOD` control operation fails.
    fn epoll_mod(epoll: &epoll::Epoll, stream_fd: RawFd, evset: epoll::EventSet) -> Result<()> {
        let event = epoll::EpollEvent::new(evset, stream_fd as u64);
        epoll
            .ctl(epoll::ControlOperation::Modify, stream_fd, event)
            .map_err(ServerError::IOError)
    }

    /// Adds a stream to the `epoll` notification structure with the `EPOLLIN` event set.
    ///
    /// # Errors
    /// `IOError` is returned when an `EPOLL_CTL_ADD` control operation fails.
    fn epoll_add(epoll: &epoll::Epoll, stream_fd: RawFd) -> Result<()> {
        epoll
            .ctl(
                epoll::ControlOperation::Add,
                stream_fd,
                epoll::EpollEvent::new(
                    epoll::EventSet::IN | epoll::EventSet::READ_HANG_UP,
                    stream_fd as u64,
                ),
            )
            .map_err(ServerError::IOError)
    }

    /// Removes a stream to the `epoll` notification structure.
    fn epoll_del(epoll: &epoll::Epoll, stream_fd: RawFd) -> Result<()> {
        epoll
            .ctl(
                epoll::ControlOperation::Delete,
                stream_fd,
                epoll::EpollEvent::new(epoll::EventSet::IN, stream_fd as u64),
            )
            .map_err(ServerError::IOError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    use crate::common::Body;
    use vmm_sys_util::tempfile::TempFile;

    fn get_temp_socket_file() -> TempFile {
        let mut path_to_socket = TempFile::new().unwrap();
        path_to_socket.remove().unwrap();
        path_to_socket
    }

    #[test]
    fn test_wait_one_connection() {
        let path_to_socket = get_temp_socket_file();

        let mut server = HttpServer::new(path_to_socket.as_path()).unwrap();
        server.start_server().unwrap();

        // Test one incoming connection.
        let mut socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        assert!(server.requests().unwrap().is_empty());

        socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                         Content-Length: 13\r\n\
                         Content-Type: application/json\r\n\r\nwhatever body",
            )
            .unwrap();

        let mut req_vec = server.requests().unwrap();
        let server_request = req_vec.remove(0);

        server
            .respond(server_request.process(|_request| {
                let mut response = Response::new(Version::Http11, StatusCode::OK);
                let response_body = b"response body";
                response.set_body(Body::new(response_body.to_vec()));
                response
            }))
            .unwrap();
        assert!(server.requests().unwrap().is_empty());

        let mut buf: [u8; 1024] = [0; 1024];
        assert!(socket.read(&mut buf[..]).unwrap() > 0);
    }

    #[test]
    fn test_connection_size_limit_exceeded() {
        let path_to_socket = get_temp_socket_file();

        let mut server = HttpServer::new(path_to_socket.as_path()).unwrap();
        server.start_server().unwrap();

        // Test one incoming connection.
        let mut socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        assert!(server.requests().unwrap().is_empty());

        socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                         Content-Length: 51201\r\n\
                         Content-Type: application/json\r\n\r\naaaaa",
            )
            .unwrap();
        assert!(server.requests().unwrap().is_empty());
        assert!(server.requests().unwrap().is_empty());
        let mut buf: [u8; 265] = [0; 265];
        assert!(socket.read(&mut buf[..]).unwrap() > 0);
        let error_message = b"HTTP/1.1 400 \r\n\
                              Server: Firecracker API\r\n\
                              Connection: keep-alive\r\n\
                              Content-Type: application/json\r\n\
                              Content-Length: 149\r\n\r\n{ \"error\": \"\
                              Request payload with size 51201 is larger than \
                              the limit of 51200 allowed by server.\nAll \
                              previous unanswered requests will be dropped.";
        assert_eq!(&buf[..], &error_message[..]);
    }

    #[test]
    fn test_set_payload_size() {
        let path_to_socket = get_temp_socket_file();

        let mut server = HttpServer::new(path_to_socket.as_path()).unwrap();
        server.start_server().unwrap();
        server.set_payload_max_size(4);

        // Test one incoming connection.
        let mut socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        assert!(server.requests().unwrap().is_empty());

        socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                         Content-Length: 5\r\n\
                         Content-Type: application/json\r\n\r\naaaaa",
            )
            .unwrap();
        assert!(server.requests().unwrap().is_empty());
        assert!(server.requests().unwrap().is_empty());
        let mut buf: [u8; 260] = [0; 260];
        assert!(socket.read(&mut buf[..]).unwrap() > 0);
        let error_message = b"HTTP/1.1 400 \r\n\
                              Server: Firecracker API\r\n\
                              Connection: keep-alive\r\n\
                              Content-Type: application/json\r\n\
                              Content-Length: 141\r\n\r\n{ \"error\": \"\
                              Request payload with size 5 is larger than the \
                              limit of 4 allowed by server.\nAll previous \
                              unanswered requests will be dropped.\" }";
        assert_eq!(&buf[..], &error_message[..]);
    }

    #[test]
    fn test_wait_one_fd_connection() {
        use std::os::unix::io::IntoRawFd;
        let path_to_socket = get_temp_socket_file();

        let socket_listener = UnixListener::bind(path_to_socket.as_path()).unwrap();
        let socket_fd = socket_listener.into_raw_fd();

        let mut server = HttpServer::new_from_fd(socket_fd).unwrap();
        server.start_server().unwrap();

        // Test one incoming connection.
        let mut socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        assert!(server.requests().unwrap().is_empty());

        socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                         Content-Length: 13\r\n\
                         Content-Type: application/json\r\n\r\nwhatever body",
            )
            .unwrap();

        let mut req_vec = server.requests().unwrap();
        let server_request = req_vec.remove(0);

        server
            .respond(server_request.process(|request| {
                assert_eq!(
                    std::str::from_utf8(&request.body.as_ref().unwrap().body).unwrap(),
                    "whatever body"
                );
                let mut response = Response::new(Version::Http11, StatusCode::OK);
                let response_body = b"response body";
                response.set_body(Body::new(response_body.to_vec()));
                response
            }))
            .unwrap();
        assert!(server.requests().unwrap().is_empty());

        let mut buf: [u8; 1024] = [0; 1024];
        assert!(socket.read(&mut buf[..]).unwrap() > 0);
        assert!(String::from_utf8_lossy(&buf).contains("response body"));
    }

    #[test]
    fn test_wait_concurrent_connections() {
        let path_to_socket = get_temp_socket_file();

        let mut server = HttpServer::new(path_to_socket.as_path()).unwrap();
        server.start_server().unwrap();

        // Test two concurrent connections.
        let mut first_socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        assert!(server.requests().unwrap().is_empty());

        first_socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                               Content-Length: 13\r\n\
                               Content-Type: application/json\r\n\r\nwhatever body",
            )
            .unwrap();
        let mut second_socket = UnixStream::connect(path_to_socket.as_path()).unwrap();

        let mut req_vec = server.requests().unwrap();
        let server_request = req_vec.remove(0);

        server
            .respond(server_request.process(|_request| {
                let mut response = Response::new(Version::Http11, StatusCode::OK);
                let response_body = b"response body";
                response.set_body(Body::new(response_body.to_vec()));
                response
            }))
            .unwrap();
        second_socket
            .write_all(
                b"GET /machine-config HTTP/1.1\r\n\
                                Content-Type: application/json\r\n\r\n",
            )
            .unwrap();

        let mut req_vec = server.requests().unwrap();
        let second_server_request = req_vec.remove(0);

        assert_eq!(
            second_server_request.request,
            Request::try_from(
                b"GET /machine-config HTTP/1.1\r\n\
            Content-Type: application/json\r\n\r\n",
                None
            )
            .unwrap()
        );

        let mut buf: [u8; 1024] = [0; 1024];
        assert!(first_socket.read(&mut buf[..]).unwrap() > 0);
        first_socket.shutdown(std::net::Shutdown::Both).unwrap();

        server
            .respond(second_server_request.process(|_request| {
                let mut response = Response::new(Version::Http11, StatusCode::OK);
                let response_body = b"response second body";
                response.set_body(Body::new(response_body.to_vec()));
                response
            }))
            .unwrap();

        assert!(server.requests().unwrap().is_empty());
        let mut buf: [u8; 1024] = [0; 1024];
        assert!(second_socket.read(&mut buf[..]).unwrap() > 0);
        second_socket.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(server.requests().unwrap().is_empty());
    }

    #[test]
    fn test_wait_expect_connection() {
        let path_to_socket = get_temp_socket_file();

        let mut server = HttpServer::new(path_to_socket.as_path()).unwrap();
        server.start_server().unwrap();

        // Test one incoming connection with `Expect: 100-continue`.
        let mut socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        assert!(server.requests().unwrap().is_empty());

        socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                         Content-Length: 13\r\n\
                         Expect: 100-continue\r\n\r\n",
            )
            .unwrap();
        // `wait` on server to receive what the client set on the socket.
        // This will set the stream direction to `Outgoing`, as we need to send a `100 CONTINUE` response.
        let req_vec = server.requests().unwrap();
        assert!(req_vec.is_empty());
        // Another `wait`, this time to send the response.
        // Will be called because of an `EPOLLOUT` notification.
        let req_vec = server.requests().unwrap();
        assert!(req_vec.is_empty());
        let mut buf: [u8; 1024] = [0; 1024];
        assert!(socket.read(&mut buf[..]).unwrap() > 0);

        socket.write_all(b"whatever body").unwrap();
        let mut req_vec = server.requests().unwrap();
        let server_request = req_vec.remove(0);

        server
            .respond(server_request.process(|_request| {
                let mut response = Response::new(Version::Http11, StatusCode::OK);
                let response_body = b"response body";
                response.set_body(Body::new(response_body.to_vec()));
                response
            }))
            .unwrap();

        let req_vec = server.requests().unwrap();
        assert!(req_vec.is_empty());

        let mut buf: [u8; 1024] = [0; 1024];
        assert!(socket.read(&mut buf[..]).unwrap() > 0);
    }

    #[test]
    fn test_wait_many_connections() {
        let path_to_socket = get_temp_socket_file();

        let mut server = HttpServer::new(path_to_socket.as_path()).unwrap();
        server.start_server().unwrap();

        let mut sockets: Vec<UnixStream> = Vec::with_capacity(MAX_CONNECTIONS + 1);
        for _ in 0..MAX_CONNECTIONS {
            sockets.push(UnixStream::connect(path_to_socket.as_path()).unwrap());
            assert!(server.requests().unwrap().is_empty());
        }

        sockets.push(UnixStream::connect(path_to_socket.as_path()).unwrap());
        assert!(server.requests().unwrap().is_empty());
        let mut buf: [u8; 120] = [0; 120];
        sockets[MAX_CONNECTIONS].read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], SERVER_FULL_ERROR_MESSAGE);
        assert_eq!(server.connections.len(), 10);
        {
            // Drop this stream.
            let _refused_stream = sockets.pop().unwrap();
        }
        assert_eq!(server.connections.len(), 10);

        // Check that the server detects a connection shutdown.
        let sock: &UnixStream = sockets.get(0).unwrap();
        sock.shutdown(Shutdown::Both).unwrap();
        assert!(server.requests().unwrap().is_empty());
        // Server should drop a closed connection.
        assert_eq!(server.connections.len(), 9);

        // Close the backing FD of this connection by dropping
        // it out of scope.
        {
            // Enforce the drop call on the stream
            let _sock = sockets.pop().unwrap();
        }
        assert!(server.requests().unwrap().is_empty());
        // Server should drop a closed connection.
        assert_eq!(server.connections.len(), 8);

        let sock: &UnixStream = sockets.get(1).unwrap();
        // Close both the read and write sides of the socket
        // separately and check that the server detects it.
        sock.shutdown(Shutdown::Read).unwrap();
        sock.shutdown(Shutdown::Write).unwrap();
        assert!(server.requests().unwrap().is_empty());
        // Server should drop a closed connection.
        assert_eq!(server.connections.len(), 7);
    }

    #[test]
    fn test_wait_parse_error() {
        let path_to_socket = get_temp_socket_file();

        let mut server = HttpServer::new(path_to_socket.as_path()).unwrap();
        server.start_server().unwrap();

        // Test one incoming connection.
        let mut socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        socket.set_nonblocking(true).unwrap();
        assert!(server.requests().unwrap().is_empty());

        socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                         Content-Length: alpha\r\n\
                         Content-Type: application/json\r\n\r\nwhatever body",
            )
            .unwrap();

        assert!(server.requests().unwrap().is_empty());
        assert!(server.requests().unwrap().is_empty());
        let mut buf: [u8; 255] = [0; 255];
        assert!(socket.read(&mut buf[..]).unwrap() > 0);
        let error_message = b"HTTP/1.1 400 \r\n\
                              Server: Firecracker API\r\n\
                              Connection: keep-alive\r\n\
                              Content-Type: application/json\r\n\
                              Content-Length: 136\r\n\r\n{ \"error\": \"Invalid header. \
                              Reason: Invalid value. Key:Content-Length; Value: alpha\nAll previous unanswered requests will be dropped.\" }";
        assert_eq!(&buf[..], &error_message[..]);

        socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                         Content-Length: alpha\r\n\
                         Content-Type: application/json\r\n\r\nwhatever body",
            )
            .unwrap();
    }

    #[test]
    fn test_wait_in_flight_responses() {
        let path_to_socket = get_temp_socket_file();

        let mut server = HttpServer::new(path_to_socket.as_path()).unwrap();
        server.start_server().unwrap();

        // Test a connection dropped and then a new one appearing
        // before the user had a chance to send the response to the
        // first one.
        let mut first_socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        assert!(server.requests().unwrap().is_empty());

        first_socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                               Content-Length: 13\r\n\
                               Content-Type: application/json\r\n\r\nwhatever body",
            )
            .unwrap();

        let mut req_vec = server.requests().unwrap();
        let server_request = req_vec.remove(0);

        first_socket.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(server.requests().unwrap().is_empty());
        let mut second_socket = UnixStream::connect(path_to_socket.as_path()).unwrap();
        second_socket.set_nonblocking(true).unwrap();
        assert!(server.requests().unwrap().is_empty());

        server
            .enqueue_responses(vec![server_request.process(|_request| {
                let mut response = Response::new(Version::Http11, StatusCode::OK);
                let response_body = b"response body";
                response.set_body(Body::new(response_body.to_vec()));
                response
            })])
            .unwrap();
        assert!(server.requests().unwrap().is_empty());
        assert_eq!(server.connections.len(), 1);
        let mut buf: [u8; 1024] = [0; 1024];
        assert!(second_socket.read(&mut buf[..]).is_err());

        second_socket
            .write_all(
                b"GET /machine-config HTTP/1.1\r\n\
                                Content-Type: application/json\r\n\r\n",
            )
            .unwrap();

        let mut req_vec = server.requests().unwrap();
        let second_server_request = req_vec.remove(0);

        assert_eq!(
            second_server_request.request,
            Request::try_from(
                b"GET /machine-config HTTP/1.1\r\n\
            Content-Type: application/json\r\n\r\n",
                None
            )
            .unwrap()
        );

        server
            .respond(second_server_request.process(|_request| {
                let mut response = Response::new(Version::Http11, StatusCode::OK);
                let response_body = b"response second body";
                response.set_body(Body::new(response_body.to_vec()));
                response
            }))
            .unwrap();

        assert!(server.requests().unwrap().is_empty());
        let mut buf: [u8; 1024] = [0; 1024];
        assert!(second_socket.read(&mut buf[..]).unwrap() > 0);
        second_socket.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(server.requests().is_ok());
    }
}
