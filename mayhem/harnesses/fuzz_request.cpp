// Cutelyst request handling end to end, without sockets: Cutelyst::TestEngine::createRequest()
// (the exported engine upstream's own tests use) builds a Request from a fuzzed method, path,
// query, headers and body, and runs it through the Dispatcher (Path / Chained matching, args,
// captures) into actions that parse the query string, cookies, url-encoded / JSON / CBOR /
// multipart bodies (Request, Utils::decodePercentEncoding, MultiPartFormDataParser, Headers).
//
// Input layout (FuzzedDataProvider): method, path, query, up to 8 header (name, value) pairs,
// then the rest is the body. The Application, controllers and engine persist across inputs;
// each createRequest() gets a fresh Context/Request, so an input's result depends only on it.
#include "fuzz_app.h"
#include "fuzz_common.h"

#include <Cutelyst/testengine.hpp>

#include <fuzzer/FuzzedDataProvider.h>

using namespace Cutelyst;
using namespace Qt::Literals::StringLiterals;

namespace {

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
        new cutelyst_fuzz::FuzzRoot(this);
        new cutelyst_fuzz::FuzzNs(this);
        return true;
    }
};

TestEngine *g_engine = nullptr;

const char *const kMethods[] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"};
const char *const kHeaders[] = {"Content-Type",
                                "Cookie",
                                "Authorization",
                                "Proxy-Authorization",
                                "If-Modified-Since",
                                "X-Requested-With",
                                "Host",
                                "Content-Disposition",
                                "Accept",
                                "Sequential"};

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    cutelyst_fuzz::ensureApp();
    auto *app = new FuzzApp;
    g_engine  = new TestEngine(app, {});
    if (!g_engine->init()) {
        abort();
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    QByteArray method;
    if (fdp.ConsumeBool()) {
        method = fdp.PickValueInArray(kMethods);
    } else {
        method = QByteArray::fromStdString(fdp.ConsumeRandomLengthString(16));
    }
    const QByteArray path  = QByteArray::fromStdString(fdp.ConsumeRandomLengthString(256));
    // EngineRequest::setPath (Cutelyst/enginerequest.h:130-137) requires a leading '/', and
    // TestEngine::createRequest passes the path to it unchecked (testengine.cpp:41-42).
    if (!path.startsWith('/')) {
        return -1;
    }
    const QByteArray query = QByteArray::fromStdString(fdp.ConsumeRandomLengthString(512));

    Headers headers;
    const int nHeaders = fdp.ConsumeIntegralInRange<int>(0, 8);
    for (int i = 0; i < nHeaders; ++i) {
        QByteArray name;
        if (fdp.ConsumeBool()) {
            name = fdp.PickValueInArray(kHeaders);
        } else {
            name = QByteArray::fromStdString(fdp.ConsumeRandomLengthString(32));
        }
        headers.pushHeader(name, QByteArray::fromStdString(fdp.ConsumeRandomLengthString(512)));
    }

    QByteArray body = QByteArray::fromStdString(fdp.ConsumeRemainingBytesAsString());
    const auto res  = g_engine->createRequest(method, path, query, headers, &body);
    (void) res.body.size();
    return 0;
}

#include "fuzz_request.moc"
