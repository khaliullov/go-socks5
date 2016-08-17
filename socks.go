package main

import (`fmt`; `net`; `strconv`; `io`; `time`; `errors`)

const DEFAULT_HOST = `0.0.0.0`
const DEFAULT_PORT = `1080`
const DEFAULT_CONNECTION_TIMEOUT = 5

const SOCKS_VERSION = 5  // only 5th version is supported
const SOCKS_RESERVED = 0

const (
    SOCKS_AUTH_NO_AUTHENTICATION_REQUIRED = iota
    SOCKS_AUTH_GSSAPI
    SOCKS_AUTH_USERNAME_PASSWORD
)

const (
    SOCKS_CMD_CONNECT = 1
    SOCKS_CMD_BIND = 2
    SOCKS_CMD_UDP_ALLOCATE = 3
)

const (
    SOCKS_ADDR_IPV4 = 1
    SOCKS_ADDR_DOMAINNAME = 3
    SOCKS_ADDR_IPV6 = 4
)

const (
    SOCKS_REPLY_SUCCEEDED = iota
    SOCKS_REPLY_GENERAL_FAILURE
    SOCKS_REPLY_CONNECTION_NOT_ALLOWED
    SOCKS_REPLY_NETWORK_UNREACHABLE
    SOCKS_REPLY_HOST_UNREACHABLE
    SOCKS_REPLY_CONNECTION_REFUCED
    SOCKS_REPLY_TTL_EXPIRED
    SOCKS_REPLY_COMMAND_NOT_SUPPORTED
    SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED
)

const SOCKS_ERROR_NO_ACCEPTABLE_METHODS = 0xFF

func proxy(writer io.Writer, reader io.Reader, eCh chan error) {
    _, err := io.Copy(writer, reader)
    eCh<- err
}

func auth(client net.Conn) (authenticated bool) {
    authenticated = false
    nMethods := []byte{0}
    
    if _, err := io.ReadAtLeast(client, nMethods, 1); err != nil {
        client.Write([]byte{SOCKS_VERSION, SOCKS_ERROR_NO_ACCEPTABLE_METHODS})
        return
    }

    auths := make([]byte, int(nMethods[0]))
    
    if _, err := io.ReadAtLeast(client, auths, int(nMethods[0])); err != nil {
        client.Write([]byte{SOCKS_VERSION, SOCKS_ERROR_NO_ACCEPTABLE_METHODS})
        return
    }

    for i := 0; i < int(nMethods[0]); i++ {
        if auths[i] == SOCKS_AUTH_NO_AUTHENTICATION_REQUIRED {
             authenticated = true
        }
    }

    if authenticated == false {
        client.Write([]byte{SOCKS_VERSION, SOCKS_ERROR_NO_ACCEPTABLE_METHODS})
        return
    }

    client.Write([]byte{SOCKS_VERSION, SOCKS_AUTH_NO_AUTHENTICATION_REQUIRED})
    return
}

func processRequest(client net.Conn) (net.Conn, error) {
    header := make([]byte, 5)
    if _, err := io.ReadAtLeast(client, header, 5); err != nil {
        client.Write([]byte{SOCKS_VERSION, SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                            SOCKS_RESERVED, SOCKS_ADDR_IPV4, 0, 0, 0, 0, 0,
                            0})
        return nil, errors.New("Failed to read header")
    }
     
    if (header[1] != SOCKS_CMD_CONNECT) {
        client.Write([]byte{SOCKS_VERSION, SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                            SOCKS_RESERVED, SOCKS_ADDR_IPV4, 0, 0, 0, 0, 0,
                            0})
        return nil, errors.New("Only connect commad is supported")
    }
    var nAddrSize int = 5
    switch header[3] {
    case SOCKS_ADDR_IPV4:
        nAddrSize = 5
    case SOCKS_ADDR_DOMAINNAME:
        nAddrSize = int(header[4])
    case SOCKS_ADDR_IPV6:
        nAddrSize = 17
    }

    address := make([]byte, nAddrSize)
    if _, err := io.ReadAtLeast(client, address, nAddrSize); err != nil {
        client.Write([]byte{SOCKS_VERSION, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
                            SOCKS_RESERVED, SOCKS_ADDR_IPV4, 0, 0, 0, 0, 0,
                            0})
        return nil, errors.New("Failed to read dst address")
    }

    var host, port string
    switch header[3] {
    case SOCKS_ADDR_IPV4:
        host = fmt.Sprintf("%[1]d.%[2]d.%[3]d.%[4]d", header[4], address[0],
                           address[1], address[2])
    case SOCKS_ADDR_DOMAINNAME:
        host = string(address[0:nAddrSize-2])
    case SOCKS_ADDR_IPV6:
        host = fmt.Sprintf("[%[1]x:%[2]x:%[3]x:%[4]x:%[5]x:%[6]x:%[7]x:%[8]x]",
                           int(address[0]) << 8 + int(address[1]),
                           int(address[2]) << 8 + int(address[3]),
                           int(address[4]) << 8 + int(address[5]),
                           int(address[6]) << 8 + int(address[7]),
                           int(address[8]) << 8 + int(address[9]),
                           int(address[10]) << 8 + int(address[11]),
                           int(address[12]) << 8 + int(address[13]),
                           int(address[14]) << 8 + int(address[15]))
    }
    port = strconv.Itoa(int(address[nAddrSize-2]) << 8 + int(address[nAddrSize-1]))
    rs, err := net.DialTimeout("tcp", host + ":" + port, time.Second * time.Duration(DEFAULT_CONNECTION_TIMEOUT))
    if err != nil {
        client.Write([]byte{SOCKS_VERSION, SOCKS_REPLY_CONNECTION_REFUCED,
                            SOCKS_RESERVED, SOCKS_ADDR_IPV4, 0, 0, 0, 0, 0,
                            0})
        return nil, errors.New("Failed to connect")
    }
    client.Write([]byte{SOCKS_VERSION, SOCKS_REPLY_SUCCEEDED, SOCKS_RESERVED,
                        SOCKS_ADDR_IPV4, 0, 0, 0, 0, 0, 0})
    return rs, nil
}

func handleRequest(localSock net.Conn) {
    cErr := make(chan error)

    defer localSock.Close()

    version := []byte{0}

    if _, err := localSock.Read(version); err != nil {
        localSock.Write([]byte{SOCKS_VERSION, SOCKS_ERROR_NO_ACCEPTABLE_METHODS})
        return
    }
    
    if version[0] != SOCKS_VERSION {  // socks4, socks4a are not supported
        localSock.Write([]byte{SOCKS_VERSION, SOCKS_ERROR_NO_ACCEPTABLE_METHODS})
        return
    }
    
    if authenticated := auth(localSock); authenticated == false {
        return
    }

    remoteSock, err := processRequest(localSock)
    if err != nil {
        return
    }
    
    defer remoteSock.Close()

    go proxy(localSock, remoteSock, cErr)
    go proxy(remoteSock, localSock, cErr)

    for i := 0; i < 2; i++ {
        <-cErr
    }
    // fmt.Println("here")
}

func main() {
    var host string = DEFAULT_HOST
    var port string = DEFAULT_PORT
    
    fmt.Println("Starting SOCKSv5 proxy on " + host + `:` + port)

    sock, err := net.Listen("tcp", host + ":" + port)
    if err != nil {
        fmt.Println(err)
        return
    }

    for {
        ls, err := sock.Accept()
        if err != nil {
            fmt.Println(err)
            continue
        }
        go handleRequest(ls)
    }
}
