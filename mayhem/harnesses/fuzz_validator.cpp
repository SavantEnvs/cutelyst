// Validator plugin's static validators over attacker-supplied form values:
// ValidatorEmail::validate (RFC 5321/5322 parser, IDN / UTF-8 local parts), ValidatorDomain::
// validate (labels, punycode/ACE conversion), ValidatorIp::validate (IPv4/IPv6, ranges).
// DNS lookups (ValidatorEmail::CheckDNS, ValidatorDomain::CheckDNS) are never enabled: they
// would make results depend on the network.
//
// Input layout: byte 0 = email options/threshold selector, byte 1 = IP constraints, rest = value.
#include "fuzz_common.h"

#include <Cutelyst/Plugins/Utils/Validator/validatordomain.h>
#include <Cutelyst/Plugins/Utils/Validator/validatoremail.h>
#include <Cutelyst/Plugins/Utils/Validator/validatorip.h>

#include <cstdint>

using namespace Cutelyst;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    cutelyst_fuzz::ensureApp();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) {
        return -1;
    }
    const uint8_t sel = data[0];
    const uint8_t ipc = data[1];
    const QString value =
        QString::fromUtf8(reinterpret_cast<const char *>(data + 2), qsizetype(size - 2));

    static const ValidatorEmail::Category kThresholds[] = {ValidatorEmail::Valid,
                                                           ValidatorEmail::RFC5321,
                                                           ValidatorEmail::CFWS,
                                                           ValidatorEmail::Deprecated,
                                                           ValidatorEmail::RFC5322,
                                                           ValidatorEmail::Error};
    ValidatorEmail::Options opts;
    if (sel & 1) {
        opts |= ValidatorEmail::UTF8Local;
    }
    if (sel & 2) {
        opts |= ValidatorEmail::AllowIDN;
    }
    QList<ValidatorEmail::Diagnose> diags;
    (void) ValidatorEmail::validate(value, kThresholds[(sel >> 2) % 6], opts, &diags);

    ValidatorDomain::Diagnose diag = ValidatorDomain::Valid;
    QString ace;
    (void) ValidatorDomain::validate(value, &diag, &ace);

    (void) ValidatorIp::validate(value, ValidatorIp::Constraints(ipc & 0x1f));
    return 0;
}
