// Cutelyst::Utils (exported): the three decodePercentEncoding overloads (in-place %XX / '+'
// decoding, and the key=value&... query/form splitter into ParamsMultiMap) and
// durationFromString (the "1h 30min 5s"-style duration parser).
#include "fuzz_common.h"

#include <Cutelyst/paramsmultimap.h>
#include <Cutelyst/utils.h>

#include <cstdint>
#include <vector>

using namespace Cutelyst;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    cutelyst_fuzz::ensureApp();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 0x7fffffff) {
        return -1;
    }
    // Query/form splitter on a mutable copy (it decodes in place). Exact-size heap buffer so
    // ASan sees any read past `len`.
    std::vector<char> buf(data, data + size);
    const ParamsMultiMap params = Utils::decodePercentEncoding(buf.data(), int(size));
    for (auto it = params.cbegin(); it != params.cend(); ++it) {
        (void) it.key().size();
        (void) it.value().size();
    }

    QByteArray ba(reinterpret_cast<const char *>(data), qsizetype(size));
    const QString fromBa = Utils::decodePercentEncoding(&ba);

    QString s = QString::fromUtf8(reinterpret_cast<const char *>(data), qsizetype(size));
    const QString fromStr = Utils::decodePercentEncoding(&s);
    (void) fromBa.size();
    (void) fromStr.size();

    bool ok = false;
    const auto us = Utils::durationFromString(
        QString::fromUtf8(reinterpret_cast<const char *>(data), qsizetype(size)), &ok);
    (void) us.count();
    return 0;
}
