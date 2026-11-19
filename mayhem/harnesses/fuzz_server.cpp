// Socket-level harness for Cutelyst::Server (the cutelystd protocol stack), driven through its
// public user-event-loop API: Server::start(app) listening on a unix socket in $TMPDIR.
//
// FUZZ_PROTO selects the listening socket:
//   1  http_socket (ProtocolHttp, with upgrade_h2c on)  -> request line, headers, bodies, chunked,
//      pipelining, h2c upgrade
//   2  http2_socket (ProtocolHttp2 + HPack)              -> input starts with the client preface
//   3  fastcgi_socket (ProtocolFastCGI)                  -> FastCGI records
//   4  http_socket, WebSocket frames: the harness first performs a fixed, valid WebSocket upgrade
//      of GET /ws (the app's action calls Response::webSocketHandshake()), waits for the 101, then
//      sends the input as frame bytes to ProtocolWebSocket. Bytes sent together with the upgrade
//      request are discarded by the server once it switches protocols, so the handshake has to be
//      its own round trip.
//
// Per input: connect, write the input, half-close (SHUT_WR), pump the Qt event loop until the
// server closes the connection (bounded by an iteration count, not a clock), then close. The
// server, its application and its sockets persist across inputs; each input gets its own
// connection, and the server tears that connection's state down when it closes, so an input's
// result depends only on that input.
#include "fuzz_common.h"

#include <Cutelyst/application.h>
#include <Cutelyst/context.h>
#include <Cutelyst/controller.h>
#include <Cutelyst/headers.h>
#include <Cutelyst/request.h>
#include <Cutelyst/response.h>
#include <Cutelyst/Server/server.h>
#include <Cutelyst/upload.h>

#include <QByteArray>
#include <QDir>
#include <QJsonDocument>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef FUZZ_PROTO
#error "define FUZZ_PROTO"
#endif

using namespace Cutelyst;
using namespace Qt::Literals::StringLiterals;

class FuzzRoot : public Controller
{
    Q_OBJECT
    C_NAMESPACE("")
public:
    explicit FuzzRoot(QObject *parent)
        : Controller(parent)
    {
    }

    // Catch-all: reads everything the request parsers expose and echoes a digest of it.
    C_ATTR(index, :Path)
    void index(Context *c)
    {
        Request *req = c->request();
        QByteArray out;
        out += req->method() + ' ' + req->protocol() + '\n';
        out += req->path().toUtf8() + '\n';
        out += req->uri().toEncoded() + '\n';
        out += req->hostname().toUtf8() + '\n';
        const auto query = req->queryParameters();
        for (auto it = query.cbegin(); it != query.cend(); ++it) {
            out += it.key().toUtf8() + '=' + it.value().toUtf8() + '\n';
        }
        out += req->queryKeywords().toUtf8() + '\n';
        const auto cookies = req->cookies();
        for (auto it = cookies.cbegin(); it != cookies.cend(); ++it) {
            out += it.value().name + '=' + it.value().value + '\n';
        }
        const Headers headers = req->headers();
        out += headers.contentType() + headers.contentTypeCharset() + '\n';
        out += headers.authorizationBasic() + headers.authorizationBearer() + '\n';
        const auto body = req->bodyParameters();
        for (auto it = body.cbegin(); it != body.cend(); ++it) {
            out += it.key().toUtf8() + '=' + it.value().toUtf8() + '\n';
        }
        const auto uploads = req->uploads();
        for (Upload *u : uploads) {
            out += u->name().toUtf8() + ';' + u->filename().toUtf8() + ';' + u->contentType() +
                   ';' + QByteArray::number(u->size()) + '\n';
            out += u->readAll().left(64);
        }
        const QVariant data = req->bodyData();
        out += QByteArray(data.typeName() ? data.typeName() : "") + '\n';
        if (QIODevice *io = req->body()) {
            io->seek(0);
            out += QByteArray::number(io->readAll().size()) + '\n';
        }
        c->response()->setContentType("text/plain"_ba);
        c->response()->setBody(out);
    }

    C_ATTR(ws, :Local)
    void ws(Context *c)
    {
        Response *res = c->response();
        if (!res->webSocketHandshake()) {
            res->setStatus(Response::BadRequest);
            return;
        }
        Request *req = c->request();
        connect(req, &Request::webSocketTextMessage, this,
                [](const QString &message, Context *ctx) {
            ctx->response()->webSocketTextMessage(message);
        });
        connect(req, &Request::webSocketBinaryMessage, this,
                [](const QByteArray &message, Context *ctx) {
            ctx->response()->webSocketBinaryMessage(message);
        });
        connect(req, &Request::webSocketTextFrame, this,
                [](const QString &message, bool, Context *) { (void) message.size(); });
        connect(req, &Request::webSocketBinaryFrame, this,
                [](const QByteArray &message, bool, Context *) { (void) message.size(); });
        connect(req, &Request::webSocketPong, this,
                [](const QByteArray &payload, Context *) { (void) payload.size(); });
    }
};

class FuzzApp : public Application
{
    Q_OBJECT
public:
    explicit FuzzApp(QObject *parent = nullptr)
        : Application(parent)
    {
    }
    bool init() override
    {
        new FuzzRoot(this);
        return true;
    }
};

static std::string g_sockPath;

// Event-loop rounds to pump while waiting for the server; bounded by count, never by time.
static constexpr int kMaxRounds = 4000;

static void pump()
{
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
}

static int connectClient()
{
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        abort();
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, g_sockPath.c_str(), g_sockPath.size() + 1);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        abort(); // the listening server must exist; anything else is a harness failure
    }
    return fd;
}

// Drain whatever the server sent. Returns false once the server closed the connection.
static bool drain(int fd, QByteArray *seen)
{
    char buf[16384];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            if (seen && seen->size() < 65536) {
                seen->append(buf, n);
            }
            continue;
        }
        if (n == 0) {
            return false;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return true;
        }
        return false; // ECONNRESET etc.
    }
}

// Write all of data (non-blocking, pumping the server in between). False if the peer went away.
static bool writeAll(int fd, const uint8_t *data, size_t size)
{
    size_t off = 0;
    int rounds = 0;
    while (off < size) {
        ssize_t n = ::send(fd, data + off, size - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += size_t(n);
            continue;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return false;
        }
        pump();
        if (!drain(fd, nullptr) || ++rounds > kMaxRounds) {
            return false;
        }
    }
    return true;
}

static bool waitFor(int fd, QByteArray *seen, const QByteArray &needle)
{
    for (int i = 0; i < kMaxRounds; ++i) {
        pump();
        if (!drain(fd, seen)) {
            return false;
        }
        if (seen->contains(needle)) {
            return true;
        }
    }
    return false;
}

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    cutelyst_fuzz::ensureApp();

    QByteArray tmpl = qgetenv("TMPDIR");
    if (tmpl.isEmpty()) {
        tmpl = "/tmp";
    }
    tmpl += "/cutelyst-fuzz-XXXXXX";
    if (!mkdtemp(tmpl.data())) {
        abort();
    }
    g_sockPath = tmpl.toStdString() + "/s";

    auto *app    = new FuzzApp;
    auto *server = new Server;
    const QStringList sock{QString::fromStdString(g_sockPath)};
#if FUZZ_PROTO == 1
    server->setHttpSocket(sock);
    server->setUpgradeH2c(true);
    server->setBufferSize(16393); // HTTP/2 (h2c upgrade target) refuses less: 2^14 + 9
#elif FUZZ_PROTO == 2
    server->setHttp2Socket(sock);
    server->setBufferSize(16393);
#elif FUZZ_PROTO == 3
    server->setFastcgiSocket(sock);
#elif FUZZ_PROTO == 4
    server->setHttpSocket(sock);
#endif
    if (!server->start(app)) {
        abort();
    }
    for (int i = 0; i < 100; ++i) {
        pump();
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int fd = connectClient();

#if FUZZ_PROTO == 4
    static const char upgrade[] = "GET /ws HTTP/1.1\r\n"
                                  "Host: localhost\r\n"
                                  "Upgrade: websocket\r\n"
                                  "Connection: Upgrade\r\n"
                                  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                  "Sec-WebSocket-Version: 13\r\n\r\n";
    QByteArray seen;
    if (!writeAll(fd, reinterpret_cast<const uint8_t *>(upgrade), sizeof(upgrade) - 1) ||
        !waitFor(fd, &seen, "\r\n\r\n"_ba) || !seen.startsWith("HTTP/1.1 101")) {
        abort(); // the fixed handshake must always succeed
    }
#endif

    bool open = writeAll(fd, data, size);
    if (open) {
        ::shutdown(fd, SHUT_WR);
        for (int i = 0; i < kMaxRounds && open; ++i) {
            pump();
            open = drain(fd, nullptr);
        }
    }
    ::close(fd);
    for (int i = 0; i < 16; ++i) {
        pump();
    }
    return 0;
}

#include "fuzz_server.moc"
