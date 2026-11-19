// Shared setup for the Cutelyst fuzz harnesses: one QCoreApplication per process, quiet logging.
#pragma once

#include <QCoreApplication>
#include <QLoggingCategory>

#include <cstdlib>

namespace cutelyst_fuzz {

inline void quietHandler(QtMsgType type, const QMessageLogContext &, const QString &)
{
    // qFatal must still kill the process so Mayhem sees it; everything else is noise.
    if (type == QtFatalMsg) {
        abort();
    }
}

inline QCoreApplication *ensureApp()
{
    static int argc     = 1;
    static char name[]  = "cutelyst-fuzz";
    static char *argv[] = {name, nullptr};
    if (!QCoreApplication::instance()) {
        qInstallMessageHandler(quietHandler);
        new QCoreApplication(argc, argv);
    }
    return QCoreApplication::instance();
}

} // namespace cutelyst_fuzz
