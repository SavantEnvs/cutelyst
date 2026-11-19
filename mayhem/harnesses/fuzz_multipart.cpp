// Cutelyst::MultiPartFormDataParser::parse() (exported): the multipart/form-data boundary scanner
// and part-header parser, plus Upload's Content-Disposition name/filename parsing.
//
// Input layout: byte 0 picks the parser's internal buffer size (small sizes hit the
// buffer-refill paths), then a Content-Type header value up to the first '\n', then the body.
#include "fuzz_common.h"

#include <Cutelyst/multipartformdataparser.h>
#include <Cutelyst/upload.h>

#include <QBuffer>

#include <cstdint>

using namespace Cutelyst;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    cutelyst_fuzz::ensureApp();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) {
        return -1;
    }
    static const int kBufferSizes[] = {1, 2, 3, 7, 16, 64, 512, 4096};
    const int bufferSize = kBufferSizes[data[0] & 7];

    QByteArray rest(reinterpret_cast<const char *>(data + 1), qsizetype(size - 1));
    const qsizetype nl = rest.indexOf('\n');
    QByteArray contentType;
    QByteArray body;
    if (nl < 0) {
        contentType = rest;
    } else {
        contentType = rest.left(nl);
        body        = rest.mid(nl + 1);
    }

    QBuffer device(&body);
    device.open(QIODevice::ReadOnly);
    const Uploads uploads = MultiPartFormDataParser::parse(&device, contentType, bufferSize);
    for (Upload *u : uploads) {
        (void) u->name();
        (void) u->filename();
        (void) u->contentType();
        (void) u->headers().keys();
        (void) u->size();
        if (u->open(QIODevice::ReadOnly) || u->isOpen()) {
            (void) u->readAll();
            u->seek(0);
            char c;
            while (u->getChar(&c)) {
            }
        }
    }
    qDeleteAll(uploads);
    return 0;
}
