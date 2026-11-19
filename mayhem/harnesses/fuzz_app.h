// Application + controllers shared by the TestEngine-driven harnesses (fuzz_request,
// fuzz_staticsimple). The actions read everything the Request parsers expose (query, cookies,
// body params, uploads, JSON/CBOR body) and cover Path, Local, Args, Chained and CaptureArgs
// dispatch, mirroring the controllers upstream's own tests register (tests/coverageobject.h).
#pragma once

#include <Cutelyst/application.h>
#include <Cutelyst/context.h>
#include <Cutelyst/controller.h>
#include <Cutelyst/headers.h>
#include <Cutelyst/request.h>
#include <Cutelyst/response.h>
#include <Cutelyst/upload.h>

#include <QJsonDocument>

namespace cutelyst_fuzz {

using namespace Cutelyst;
using namespace Qt::Literals::StringLiterals;

inline QByteArray digestRequest(Context *c)
{
    Request *req = c->request();
    QByteArray out;
    out += req->method() + ' ' + req->protocol() + '\n';
    out += req->path().toUtf8() + '|' + req->match().toUtf8() + '\n';
    out += req->arguments().join(u'/').toUtf8() + '|' + req->captures().join(u'/').toUtf8() + '\n';
    out += req->uri().toEncoded() + '\n';
    out += req->base().toUtf8() + '\n';
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
    out += headers.ifModifiedSinceDateTime().toString().toUtf8() + '\n';
    const auto body = req->bodyParameters();
    for (auto it = body.cbegin(); it != body.cend(); ++it) {
        out += it.key().toUtf8() + '=' + it.value().toUtf8() + '\n';
    }
    const auto uploads = req->uploads();
    for (Upload *u : uploads) {
        out += u->name().toUtf8() + ';' + u->filename().toUtf8() + ';' + u->contentType() + ';' +
               QByteArray::number(u->size()) + '\n';
        out += u->readAll().left(64);
    }
    const QVariant data = req->bodyData();
    out += QByteArray(data.typeName() ? data.typeName() : "") + '\n';
    out += req->bodyJsonDocument().toJson(QJsonDocument::Compact).left(256) + '\n';
    out += req->bodyParametersVariant().keys().join(u',').toUtf8() + '\n';
    out += QByteArray::number(req->xhr()) + QByteArray::number(req->secure());
    return out;
}

class FuzzRoot : public Controller
{
    Q_OBJECT
    C_NAMESPACE("")
public:
    explicit FuzzRoot(QObject *parent)
        : Controller(parent)
    {
    }

    C_ATTR(index, :Path)
    void index(Context *c) { c->response()->setBody(digestRequest(c)); }

    C_ATTR(one, :Local :Args(1))
    void one(Context *c, const QString &a) { c->response()->setBody(a.toUtf8() + digestRequest(c)); }

    C_ATTR(two, :Local :Args(2))
    void two(Context *c, const QString &a, const QString &b)
    {
        c->response()->setBody(a.toUtf8() + b.toUtf8() + digestRequest(c));
    }

    C_ATTR(redirect, :Local :AutoArgs)
    void redirect(Context *c, const QString &to)
    {
        c->response()->redirect(QUrl(to));
    }

    C_ATTR(chain, :Chained("/") :PathPart("chain") :CaptureArgs(1))
    void chain(Context *c, const QString &cap) { c->stash({{QStringLiteral("cap"), cap}}); }

    C_ATTR(chainItem, :Chained("chain") :PathPart("item") :Args(1))
    void chainItem(Context *c, const QString &a) { c->response()->setBody(a.toUtf8() + digestRequest(c)); }

    C_ATTR(chainMid, :Chained("chain") :AutoCaptureArgs)
    void chainMid(Context *, const QString &, const QString &) {}

    C_ATTR(chainMidEnd, :Chained("chainMid") :PathPart("end") :Args)
    void chainMidEnd(Context *c, const QStringList &args)
    {
        c->response()->setBody(args.join(u'/').toUtf8() + digestRequest(c));
    }

    C_ATTR(chainAny, :Chained("chain") :PathPart("") :Args)
    void chainAny(Context *c, const QStringList &args)
    {
        c->response()->setBody(args.join(u'|').toUtf8());
    }
};

class FuzzNs : public Controller
{
    Q_OBJECT
    C_NAMESPACE("ns/sub")
public:
    explicit FuzzNs(QObject *parent)
        : Controller(parent)
    {
    }

    C_ATTR(index, :Path :Args(0))
    void index(Context *c) { c->response()->setBody(digestRequest(c)); }

    C_ATTR(any, :Path('any') :Args)
    void any(Context *c, const QStringList &args) { c->response()->setBody(args.join(u',').toUtf8()); }

    C_ATTR(End, :Private)
    void End(Context *c) { c->response()->setHeader("X-End"_ba, "1"_ba); }
};

} // namespace cutelyst_fuzz
