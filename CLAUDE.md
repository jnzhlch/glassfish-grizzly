# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Clean build and install all modules
mvn clean install

# Skip tests during build
mvn clean install -DskipTests

# Run specific test class
mvn test -Dtest=ClassName

# Build specific module
mvn clean install -pl modules/grizzly
```

## Project Architecture

### Module Structure

The codebase is organized as a multi-module Maven project:

- **modules/grizzly**: Core NIO framework (transport, filter chains, memory management)
- **modules/http**: HTTP protocol implementation
- **modules/http-server**: HTTP server implementation
- **modules/http-servlet**: Servlet container integration (NOT fully Servlet compliant)
- **modules/websockets**: WebSocket protocol support
- **modules/comet**: Comet/long-polling support
- **modules/http2**: HTTP/2 protocol support
- **modules/http-ajp**: AJP connector for Tomcat compatibility
- **modules/portunif**: Port unification framework (run multiple protocols on single port)
- **modules/bundles**: Pre-packaged module combinations
- **extras/**: Optional extensions (connection-pool, jaxws, multipart, tls-sni)
- **samples/**: Example applications

### Core Architecture Patterns

#### Filter Chain Architecture
The framework uses a filter chain pipeline for request/response processing:
- **FilterChain**: Pipeline of processing filters
- **FilterChainContext**: Context object carrying data through the chain
- **BaseFilter**: Base implementation with lifecycle methods (onRead, onWrite, etc.)
- **AbstractCodecFilter**: Base for protocol-specific codec filters

#### Transport Layer
- **NIOTransport**: Main NIO transport using Java NIO selectors
- **NIOConnection**: Represents network connections with async I/O
- **SelectorHandler**: Manages NIO selector operations for multiplexing

#### Memory Management
- **MemoryManager**: Abstract buffer management
- **PooledMemoryManager**: Pool-based memory management for reduced GC pressure
- **CompositeBuffer**: Chainable buffer implementation for efficient data handling

### Prerequisites

- **Java 21+** for main branch (5.0.x development)
- **Maven 3.8.9+** required for building

### Module Dependencies

The minimal dependency for any Grizzly application is `grizzly-framework`. HTTP support requires `grizzly-http`. HTTP server support builds on HTTP with `grizzly-http-server`. The Servlet module further extends HTTP server but is NOT fully Servlet compliant.

Use the BOM (`grizzly-bom`) for consistent dependency versions across modules.

### Key Design Principles

1. **Non-blocking I/O**: All operations use NIO for scalability
2. **Modularity**: Clear separation of concerns with pluggable components
3. **Filter-based processing**: Chain of responsibility pattern for request handling
4. **Buffer pooling**: Reusable buffers to minimize GC overhead
5. **Zero-copy**: Composite buffers allow efficient message assembly without copying

### Version Branches

- `main`: 5.0.x (Jakarta EE 11, Java 21+)
- `4.1.x`: Jakarta EE 11 with Java 17 support
- `4.0.x`: Jakarta EE 10 (Java 11)
- `3.0.x`: Jakarta EE 9 (Java 11)
- `2.4.x`: Jakarta EE 8 (Java 8)
