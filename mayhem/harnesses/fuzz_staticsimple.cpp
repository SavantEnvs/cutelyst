// StaticSimple plugin: request path -> file under the include path (traversal checks, dirs /
// serveDirsOnly matching, If-Modified-Since, MIME lookup), via Cutelyst::TestEngine.
//
// LLVMFuzzerInitialize creates, under $TMPDIR, a web root `inc/` (with files, a `forced/` dir and
// a subdir) and a canary file *outside* it. Two engines are kept: one with serveDirsOnly off and
// one with it on (as upstream's tests/teststaticsimple.cpp). These files and engines are never
// modified, so an input's result depends only on the input. Serving the canary means the
// plugin let a request escape the include path: the harness aborts.
//
// Input layout (FuzzedDataProvider): engine selector, If-Modified-Since value, up to 4 extra
// header pairs, then the rest is the request path.
#include <Cutelyst/application.h>
#include <Cutelyst/context.h>
#include <Cutelyst/controller.h>
#include <Cutelyst/headers.h>
#include <Cutelyst/response.h>
#include "fuzz_common.h"

#include <Cutelyst/Plugins/StaticSimple/staticsimple.h>
#include <Cutelyst/testengine.hpp>

#include <QDir>
#include <QFile>

#include <fuzzer/FuzzedDataProvider.h>

using namespace Cutelyst;
using namespace Qt::Literals::StringLiterals;

namespace {

// Fallback for paths StaticSimple does not serve: a constant body, so the only way the canary can
// reach the response is StaticSimple reading it from disk.
class FuzzFallback : public Controller
{
    Q_OBJECT
    C_NAMESPACE("")
public:
    explicit FuzzFallback(QObject *parent)
        : Controller(parent)
    {
    }
    C_ATTR(index, :Path)
    void index(Context *c)
    {
        c->response()->setStatus(Response::NotFound);
        c->response()->setBody("not found"_ba);
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
        new FuzzFallback(this);
        return true;
    }
};

const QByteArray kCanary = "CUTELYST_FUZZ_CANARY_OUTSIDE_INCLUDE_PATH"_ba;
TestEngine *g_engines[2] = {nullptr, nullptr};

void writeFile(const QString &path, const QByteArray &content)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly) || f.write(content) != content.size()) {
        abort();
    }
}

TestEngine *makeEngine(const QString &inc, bool dirsOnly)
{
    auto *app    = new FuzzApp;
    auto *engine = new TestEngine(app, {});
    auto *plug   = new StaticSimple(app);
    plug->setIncludePaths({inc});
    plug->setDirs({u"forced"_s, u"sub/deep"_s});
    plug->setServeDirsOnly(dirsOnly);
    if (!engine->init()) {
        abort();
    }
    return engine;
}

const char *const kHeaders[] = {"If-Modified-Since", "Host", "Accept", "Range", "Accept-Encoding"};

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    cutelyst_fuzz::ensureApp();

    QByteArray tmpl = qgetenv("TMPDIR");
    if (tmpl.isEmpty()) {
        tmpl = "/tmp";
    }
    tmpl += "/cutelyst-static-XXXXXX";
    if (!mkdtemp(tmpl.data())) {
        abort();
    }
    const QString root = QString::fromLocal8Bit(tmpl);
    QDir(root).mkpath(u"inc/forced"_s);
    QDir(root).mkpath(u"inc/sub/deep"_s);
    writeFile(root + u"/secret.txt"_s, kCanary);
    writeFile(root + u"/inc/index.html"_s, "<html>index</html>"_ba);
    writeFile(root + u"/inc/style.css"_s, "body{}"_ba);
    writeFile(root + u"/inc/forced/a.txt"_s, "forced a"_ba);
    writeFile(root + u"/inc/sub/deep/b.json"_s, "{\"b\":1}"_ba);
    writeFile(root + u"/inc/sub/img.png"_s, "\x89PNG\r\n"_ba);

    g_engines[0] = makeEngine(root + u"/inc"_s, false);
    g_engines[1] = makeEngine(root + u"/inc"_s, true);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    TestEngine *engine = g_engines[fdp.ConsumeBool() ? 1 : 0];

    Headers headers;
    if (fdp.ConsumeBool()) {
        headers.setHeader("If-Modified-Since"_ba,
                          QByteArray::fromStdString(fdp.ConsumeRandomLengthString(64)));
    }
    const int n = fdp.ConsumeIntegralInRange<int>(0, 4);
    for (int i = 0; i < n; ++i) {
        headers.pushHeader(fdp.PickValueInArray(kHeaders),
                           QByteArray::fromStdString(fdp.ConsumeRandomLengthString(64)));
    }
    const QByteArray path = QByteArray::fromStdString(fdp.ConsumeRemainingBytesAsString());
    // EngineRequest::setPath (Cutelyst/enginerequest.h:130-137) requires a leading '/', and
    // TestEngine::createRequest passes the path to it unchecked (testengine.cpp:41-42).
    if (!path.startsWith('/')) {
        return -1;
    }

    const auto res = engine->createRequest("GET"_ba, path, {}, headers, nullptr);
    if (res.body == kCanary) { // the whole body is the file: error pages may echo the path
        // StaticSimple served a file outside its include path.
        abort();
    }
    return 0;
}

#include "fuzz_staticsimple.moc"
