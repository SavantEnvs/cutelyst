// Cutelyst::Headers accessors over client-controlled header values: Content-Type / charset /
// Content-Disposition parsing, HTTP date parsing (Date, If-Modified-Since), Authorization and
// Proxy-Authorization Basic (base64 + user:password split) and Bearer, If-Match / If-None-Match
// ETag list matching.
//
// Input layout: the input is split on '\n' into header values assigned in order to the names
// below (a missing value is simply absent); the last line is also the ETag to match.
#include "fuzz_common.h"

#include <Cutelyst/headers.h>

#include <QDateTime>
#include <QTimeZone>

#include <cstdint>

using namespace Cutelyst;
using namespace Qt::Literals::StringLiterals;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    cutelyst_fuzz::ensureApp();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const QByteArray kNames[] = {"Content-Type"_ba,
                                        "Authorization"_ba,
                                        "Proxy-Authorization"_ba,
                                        "If-Modified-Since"_ba,
                                        "Date"_ba,
                                        "If-Match"_ba,
                                        "If-None-Match"_ba,
                                        "Content-Disposition"_ba,
                                        "Content-Encoding"_ba,
                                        "Connection"_ba,
                                        "Last-Modified"_ba};
    constexpr int kN = int(sizeof(kNames) / sizeof(kNames[0]));

    const QByteArray input(reinterpret_cast<const char *>(data), qsizetype(size));
    const QList<QByteArray> lines = input.split('\n');

    Headers h;
    for (int i = 0; i < lines.size(); ++i) {
        h.pushHeader(kNames[i % kN], lines.at(i));
    }
    const QByteArray etag = lines.isEmpty() ? QByteArray{} : lines.last();

    (void) h.contentType();
    (void) h.contentTypeCharset();
    (void) h.contentIsText();
    (void) h.contentIsHtml();
    (void) h.contentIsXHtml();
    (void) h.contentIsXml();
    (void) h.contentIsJson();
    (void) h.contentLength();
    (void) h.contentDisposition();
    (void) h.contentEncoding();
    (void) h.date();
    (void) h.ifModifiedSince();
    const QDateTime ims = h.ifModifiedSinceDateTime();
    (void) h.ifModifiedSince(QDateTime::fromSecsSinceEpoch(784111777, QTimeZone::UTC));
    (void) ims.isValid();
    (void) h.ifMatch(etag);
    (void) h.ifNoneMatch(etag);
    (void) h.ifMatch(QLatin1StringView("\"abc\""));
    (void) h.ifNoneMatch(QLatin1StringView("W/\"abc\""));
    (void) h.authorization();
    (void) h.authorizationBearer();
    (void) h.authorizationBasic();
    const auto basic = h.authorizationBasicObject();
    (void) basic.user.size();
    (void) h.proxyAuthorization();
    (void) h.proxyAuthorizationBasic();
    (void) h.proxyAuthorizationBasicObject();
    (void) h.connection();
    (void) h.lastModified();
    (void) h.headersAsStrings("Content-Type"_ba);
    (void) h.keys();

    Headers copy = h;
    copy.setContentTypeCharset(etag);
    (void) copy.contentType();
    copy.setContentDispositionAttachment(etag);
    (void) copy.contentDisposition();
    (void) (copy == h);
    return 0;
}
