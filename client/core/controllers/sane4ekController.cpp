#include "sane4ekController.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QFutureWatcher>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QRandomGenerator>
#include <QSet>
#include <QSettings>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QSysInfo>
#include <QUrl>
#include <QThread>
#include <QElapsedTimer>
#include <QProcess>
#include <QRegularExpression>
#include <QTcpSocket>
#include <QTimer>
#include <QUuid>
#include <QtConcurrent>

#include <cstring>
#include <memory>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "core/controllers/selfhosted/importController.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/qrCodeUtils.h"
#include "core/utils/selfhosted/sshSession.h"
#include "core/utils/serverConfigUtils.h"

using namespace amnezia;

namespace
{
    constexpr int agentPort = 47443;
    constexpr char invitePrefix[] = "sane4ek://";
    constexpr char privateKeyPlaceholder[] = "__SANE4EK_PRIVATE_KEY__";
    constexpr char hostPlaceholder[] = "__SANE4EK_HOST__";

    QSettings &store()
    {
        static QSettings settings(QStringLiteral("Sane4ek"), QStringLiteral("Sane4ek"));
        return settings;
    }

    QJsonObject readObject(const QString &key)
    {
        return QJsonDocument::fromJson(store().value(key).toByteArray()).object();
    }

    QJsonArray readArray(const QString &key)
    {
        return QJsonDocument::fromJson(store().value(key).toByteArray()).array();
    }

    void writeJson(const QString &key, const QJsonDocument &doc)
    {
        store().setValue(key, doc.toJson(QJsonDocument::Compact));
        store().sync();
    }

    QString base64Url(const QByteArray &data)
    {
        return QString::fromLatin1(data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    }

    QString serverKeyForHost(const QString &host)
    {
        return QString::fromLatin1(QCryptographicHash::hash(host.toUtf8(), QCryptographicHash::Sha256).toHex().left(16));
    }

    QString certFingerprint(const QString &pem)
    {
        const QList<QSslCertificate> certs = QSslCertificate::fromData(pem.toUtf8(), QSsl::Pem);
        if (certs.isEmpty()) {
            return QString();
        }
        return QString::fromLatin1(certs.first().digest(QCryptographicHash::Sha256).toHex());
    }

    QByteArray ed25519PublicKey(const QByteArray &seed)
    {
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                      reinterpret_cast<const unsigned char *>(seed.constData()), seed.size());
        if (!pkey) {
            return QByteArray();
        }
        QByteArray pub(32, 0);
        size_t len = static_cast<size_t>(pub.size());
        const bool ok = EVP_PKEY_get_raw_public_key(pkey, reinterpret_cast<unsigned char *>(pub.data()), &len) == 1;
        EVP_PKEY_free(pkey);
        return ok ? pub.left(static_cast<int>(len)) : QByteArray();
    }

    QByteArray ed25519Sign(const QByteArray &seed, const QByteArray &message)
    {
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                      reinterpret_cast<const unsigned char *>(seed.constData()), seed.size());
        if (!pkey) {
            return QByteArray();
        }
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        QByteArray sig(64, 0);
        size_t len = static_cast<size_t>(sig.size());
        const bool ok = ctx && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1
                && EVP_DigestSign(ctx, reinterpret_cast<unsigned char *>(sig.data()), &len,
                                  reinterpret_cast<const unsigned char *>(message.constData()), message.size()) == 1;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ok ? sig.left(static_cast<int>(len)) : QByteArray();
    }

    bool ed25519Verify(const QByteArray &publicKey, const QByteArray &message, const QByteArray &signature)
    {
        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                     reinterpret_cast<const unsigned char *>(publicKey.constData()),
                                                     publicKey.size());
        if (!pkey) {
            return false;
        }
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        const bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1
                && EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char *>(signature.constData()), signature.size(),
                                    reinterpret_cast<const unsigned char *>(message.constData()), message.size()) == 1;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ok;
    }

    bool generateX25519(QByteArray &privateKey, QByteArray &publicKey)
    {
        unsigned char seed[32];
        if (RAND_priv_bytes(seed, sizeof(seed)) != 1) {
            return false;
        }
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, seed, sizeof(seed));
        if (!pkey) {
            return false;
        }
        unsigned char priv[32];
        unsigned char pub[32];
        size_t privLen = sizeof(priv);
        size_t pubLen = sizeof(pub);
        const bool ok = EVP_PKEY_get_raw_private_key(pkey, priv, &privLen) == 1
                && EVP_PKEY_get_raw_public_key(pkey, pub, &pubLen) == 1;
        EVP_PKEY_free(pkey);
        if (!ok) {
            return false;
        }
        privateKey = QByteArray(reinterpret_cast<const char *>(priv), static_cast<int>(privLen));
        publicKey = QByteArray(reinterpret_cast<const char *>(pub), static_cast<int>(pubLen));
        return true;
    }

    QString readResource(const QString &path)
    {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            return QString();
        }
        return QString::fromUtf8(f.readAll());
    }

    QJsonObject endpointToJson(const Sane4ekController::Endpoint &e)
    {
        return QJsonObject { { "h", e.host }, { "p", e.port }, { "f", e.fingerprint } };
    }

    // sane4ek://<base64url json> -> invite object, empty if invalid
    QJsonObject parseInvite(const QString &text)
    {
        const QString trimmed = text.trimmed();
        if (!trimmed.startsWith(QLatin1String(invitePrefix))) {
            return QJsonObject();
        }
        const QByteArray json = QByteArray::fromBase64(trimmed.mid(int(strlen(invitePrefix))).toLatin1(),
                                                       QByteArray::Base64UrlEncoding);
        const QJsonObject invite = QJsonDocument::fromJson(json).object();
        if (invite.value("t").toString().isEmpty()
            || QByteArray::fromBase64(invite.value("k").toString().toLatin1()).size() != 32
            || invite.value("s").toArray().isEmpty()) {
            return QJsonObject();
        }
        return invite;
    }

    // Round-trip time to a server in ms, -1 if it does not answer.
    // ICMP ping first; many servers drop ICMP, so then the TCP handshake time to common ports
    // (an accepted or refused connection both mean the host is alive).
    int measurePing(const QString &host)
    {
#if !defined(Q_OS_WIN) // Windows: ping has other options and localized output, TCP below is enough
        QProcess p;
        const QString bin = QFile::exists("/system/bin/ping") ? QStringLiteral("/system/bin/ping") : QStringLiteral("ping");
        p.start(bin, { "-c", "5", "-i", "0.2", "-W", "2", host }); // average of 5 replies
        if (p.waitForFinished(12000)) {
            const QString out = QString::fromLocal8Bit(p.readAllStandardOutput());
            static const QRegularExpression avgRe(R"(= [\d.]+/([\d.]+)/)");
            static const QRegularExpression oneRe(R"(time[=<]([\d.]+))");
            QRegularExpressionMatch m = avgRe.match(out);
            if (!m.hasMatch()) {
                m = oneRe.match(out);
            }
            if (m.hasMatch()) {
                return qMax(1, qRound(m.captured(1).toDouble()));
            }
        } else {
            p.kill();
            p.waitForFinished(1000);
        }
#endif

        for (int port : { 47443, 22, 443 }) {
            qint64 total = 0;
            int samples = 0;
            for (int attempt = 0; attempt < 5; ++attempt) {
                QTcpSocket socket;
                QElapsedTimer timer;
                timer.start();
                socket.connectToHost(host, static_cast<quint16>(port));
                const bool alive = socket.waitForConnected(2500) || socket.error() == QAbstractSocket::ConnectionRefusedError;
                const qint64 ms = timer.elapsed();
                socket.abort();
                if (!alive) {
                    break; // this port is filtered, try the next one
                }
                total += ms;
                samples++;
            }
            if (samples > 0) {
                return qMax(1, static_cast<int>(total / samples));
            }
        }
        return -1;
    }

    Sane4ekController::Endpoint endpointFromJson(const QJsonObject &o)
    {
        Sane4ekController::Endpoint e;
        e.host = o.value("h").toString();
        e.port = o.value("p").toInt(agentPort);
        e.fingerprint = o.value("f").toString();
        return e;
    }
}

Sane4ekController::Sane4ekController(SecureServersRepository *serversRepository, ImportController *importController,
                                     QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_importController(importController),
      m_network(new QNetworkAccessManager(this))
{
    connect(m_serversRepository, &SecureServersRepository::serverAdded, this, &Sane4ekController::adminStateChanged);
    connect(m_serversRepository, &SecureServersRepository::serverEdited, this, &Sane4ekController::adminStateChanged);
    connect(m_serversRepository, &SecureServersRepository::serverRemoved, this, &Sane4ekController::adminStateChanged);

    // Servers with the same address added before duplicates were blocked: keep one of them
    QTimer::singleShot(1000, this, &Sane4ekController::removeDuplicateServers);

    // Pings in the server list: shortly after start and whenever servers are added
    QTimer::singleShot(4000, this, &Sane4ekController::pingAll);
    connect(m_serversRepository, &SecureServersRepository::serverAdded, this, [this]() {
        QTimer::singleShot(1500, this, &Sane4ekController::pingAll);
    });

    // A user with the built-in invite gets the servers on the first start without pressing anything
    QTimer::singleShot(2500, this, [this]() {
        if (!isAdmin() && m_serversRepository->serversCount() == 0 && hasInvite()) {
            refresh();
        }
    });
}

void Sane4ekController::setBusy(bool busy)
{
    if (m_busy != busy) {
        m_busy = busy;
        emit busyChanged();
    }
}

// ------------------------------------------------------------------------------------------ admin

QList<Sane4ekController::AdminServer> Sane4ekController::adminServers() const
{
    QList<AdminServer> result;
    const QVector<QString> ids = m_serversRepository->orderedServerIds();
    for (const QString &id : ids) {
        const auto admin = m_serversRepository->selfHostedAdminConfig(id);
        if (!admin.has_value() || !admin->hasCredentials()) {
            continue;
        }
        if (!admin->containers.contains(DockerContainer::Awg2) && !admin->containers.contains(DockerContainer::Awg)) {
            continue;
        }
        AdminServer s;
        s.credentials = admin->credentials();
        s.key = serverKeyForHost(s.credentials.hostName);
        s.name = admin->description.isEmpty() ? s.credentials.hostName : admin->description;
        result.append(s);
    }
    return result;
}

bool Sane4ekController::isAdmin() const
{
    return !adminServers().isEmpty();
}

QByteArray Sane4ekController::adminSigningSeed()
{
    QByteArray seed = QByteArray::fromBase64(store().value("admin/signKey").toByteArray());
    if (seed.size() != 32) {
        seed.resize(32);
        if (RAND_priv_bytes(reinterpret_cast<unsigned char *>(seed.data()), 32) != 1) {
            return QByteArray();
        }
        store().setValue("admin/signKey", seed.toBase64());
        store().sync();
    }
    return seed;
}

QJsonArray Sane4ekController::storedInvites() const
{
    return readArray("admin/invites");
}

void Sane4ekController::storeInvites(const QJsonArray &invites)
{
    writeJson("admin/invites", QJsonDocument(invites));
    emit invitesChanged();
}

QVariantList Sane4ekController::invites() const
{
    QVariantList list;
    const QJsonArray arr = storedInvites();
    for (const QJsonValue &v : arr) {
        const QJsonObject o = v.toObject();
        QVariantMap m;
        m["id"] = o.value("id").toString();
        m["name"] = o.value("name").toString();
        m["maxDevices"] = o.value("maxDevices").toInt();
        m["created"] = QDateTime::fromSecsSinceEpoch(o.value("created").toInteger()).toString("dd.MM.yyyy");
        const qint64 expires = o.value("expires").toInteger();
        m["expires"] = expires > 0 ? QDateTime::fromSecsSinceEpoch(expires).toString("dd.MM.yyyy HH:mm") : QString();
        m["expired"] = expires > 0 && expires < QDateTime::currentSecsSinceEpoch();
        list.append(m);
    }
    return list;
}

QString Sane4ekController::createInvite(const QString &name, int maxDevices, int days)
{
    QByteArray token(18, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(token.data()), token.size()) != 1) {
        return QString();
    }
    QJsonObject invite;
    invite["id"] = QUuid::createUuid().toString(QUuid::WithoutBraces);
    invite["name"] = name.trimmed().isEmpty() ? tr("Invite") : name.trimmed().left(40);
    invite["token"] = base64Url(token);
    invite["maxDevices"] = qBound(0, maxDevices, 20);
    invite["created"] = QDateTime::currentSecsSinceEpoch();
    invite["expires"] = days > 0 ? QDateTime::currentSecsSinceEpoch() + qint64(days) * 24 * 3600 : 0;

    QJsonArray arr = storedInvites();
    arr.append(invite);
    storeInvites(arr);

    upload(); // servers need the new invite before it can be used
    return invite["id"].toString();
}

void Sane4ekController::removeInvite(const QString &inviteId)
{
    QJsonArray arr = storedInvites();
    for (int i = arr.size() - 1; i >= 0; --i) {
        if (arr.at(i).toObject().value("id").toString() == inviteId) {
            arr.removeAt(i);
        }
    }
    storeInvites(arr);
    upload(); // servers drop the peers of a removed invite
}

QString Sane4ekController::inviteLink(const QString &inviteId) const
{
    QJsonObject invite;
    for (const QJsonValue &v : storedInvites()) {
        if (v.toObject().value("id").toString() == inviteId) {
            invite = v.toObject();
        }
    }
    if (invite.isEmpty()) {
        return QString();
    }

    const QByteArray seed = QByteArray::fromBase64(store().value("admin/signKey").toByteArray());
    QJsonArray servers;
    const QJsonObject certs = readObject("admin/certs");
    for (const AdminServer &s : adminServers()) {
        const QString fp = certs.value(s.key).toObject().value("f").toString();
        if (!fp.isEmpty()) {
            servers.append(endpointToJson({ s.credentials.hostName, agentPort, fp }));
        }
    }

    if (servers.isEmpty()) {
        return QString(); // no server has the agent yet - press Upload first
    }

    QJsonObject payload;
    payload["v"] = 1;
    payload["k"] = QString::fromLatin1(ed25519PublicKey(seed).toBase64());
    payload["t"] = invite.value("token").toString();
    payload["n"] = invite.value("name").toString();
    payload["s"] = servers;
    return QString(invitePrefix) + base64Url(QJsonDocument(payload).toJson(QJsonDocument::Compact));
}

QString Sane4ekController::inviteQrCode(const QString &inviteId) const
{
    const QString link = inviteLink(inviteId);
    return link.isEmpty() ? QString() : qrCodeUtils::generatePlainQrCodeImage(link.toUtf8());
}

void Sane4ekController::upload()
{
    if (m_busy) {
        return;
    }
    const QList<AdminServer> servers = adminServers();
    if (servers.isEmpty()) {
        emit operationFinished(false, tr("No servers with AmneziaWG and SSH access"));
        return;
    }
    if (adminSigningSeed().isEmpty()) {
        emit operationFinished(false, tr("Failed to create the signing key"));
        return;
    }
    setBusy(true);

    const QString agent = readResource(":/server_scripts/sane4ek/agent.py");
    const QString dockerfile = readResource(":/server_scripts/sane4ek/Dockerfile");
    const QString install = readResource(":/server_scripts/sane4ek/install.sh");

    auto *watcher = new QFutureWatcher<QList<InstallResult>>(this);
    connect(watcher, &QFutureWatcher<QList<InstallResult>>::finished, this, [this, watcher]() {
        const QList<InstallResult> results = watcher->result();
        watcher->deleteLater();
        finishUploadPhase1(results);
    });

    watcher->setFuture(QtConcurrent::run([servers, agent, dockerfile, install]() {
        QList<InstallResult> results;
        for (const AdminServer &server : servers) {
            InstallResult r;
            r.server = server;
            SshSession ssh;
            QString out;
            auto cb = [&out](const QString &data, libssh::Client &) {
                out += data;
                return ErrorCode::NoError;
            };
            ErrorCode e = ssh.runScript(server.credentials, "mkdir -p /tmp/sane4ek-build");
            if (e == ErrorCode::NoError)
                e = ssh.uploadFileToHost(server.credentials, agent.toUtf8(), "/tmp/sane4ek-build/agent.py");
            if (e == ErrorCode::NoError)
                e = ssh.uploadFileToHost(server.credentials, dockerfile.toUtf8(), "/tmp/sane4ek-build/Dockerfile");
            if (e == ErrorCode::NoError)
                e = ssh.uploadFileToHost(server.credentials, install.toUtf8(), "/tmp/sane4ek-build/install.sh");
            if (e == ErrorCode::NoError)
            {
                // The first docker build prints nothing for minutes and the SSH read gives up on a
                // silent channel, so run the installer in the background and poll its log.
                e = ssh.runScript(server.credentials,
                                  "rm -f /tmp/sane4ek-install.log; nohup sh -c 'sh /tmp/sane4ek-build/install.sh; "
                                  "echo SANE4EK_EXIT=$?' > /tmp/sane4ek-install.log 2>&1 < /dev/null &");
                for (int attempt = 0; e == ErrorCode::NoError && attempt < 200; ++attempt) { // up to ~10 min
                    QThread::sleep(3);
                    out.clear();
                    e = ssh.runScript(server.credentials, "cat /tmp/sane4ek-install.log 2>/dev/null", cb, cb);
                    if (out.contains("SANE4EK_EXIT=")) {
                        break;
                    }
                }
            }

            const int begin = out.indexOf("-----BEGIN CERTIFICATE-----");
            const int end = out.indexOf("-----END CERTIFICATE-----");
            if (begin >= 0 && end > begin) {
                r.certPem = out.mid(begin, end - begin + int(strlen("-----END CERTIFICATE-----")));
                r.ok = true;
            } else {
                QStringList lines = out.split('\n', Qt::SkipEmptyParts);
                while (lines.size() > 2) {
                    lines.removeFirst();
                }
                const QString tail = lines.join(" / ").trimmed().right(160);
                r.error = e != ErrorCode::NoError ? QString("SSH error %1%2").arg(static_cast<int>(e)).arg(tail.isEmpty() ? "" : ": " + tail)
                                                  : (tail.isEmpty() ? QString("no output") : tail);
            }
            results.append(r);
        }
        return results;
    }));
}

void Sane4ekController::finishUploadPhase1(const QList<InstallResult> &results)
{
    // Remember certificates so that temporarily unreachable servers stay in the list
    QJsonObject certs = readObject("admin/certs");
    QJsonObject freshCerts;
    QStringList failedNames;
    QList<AdminServer> reachable;
    for (const InstallResult &r : results) {
        if (r.ok) {
            const QString fp = certFingerprint(r.certPem);
            freshCerts[r.server.key] = QJsonObject { { "h", r.server.credentials.hostName }, { "f", fp } };
            reachable.append(r.server);
        } else {
            qWarning() << "Sane4ek: agent install failed on" << r.server.name << r.error;
            failedNames.append(QString("%1 (%2)").arg(r.server.name, r.error));
            if (certs.contains(r.server.key)) {
                freshCerts[r.server.key] = certs.value(r.server.key);
            }
        }
    }
    writeJson("admin/certs", QJsonDocument(freshCerts));

    // Signed manifest: every admin server we have a certificate for
    QJsonArray manifestServers;
    for (const InstallResult &r : results) {
        const QJsonObject c = freshCerts.value(r.server.key).toObject();
        if (c.isEmpty()) {
            continue;
        }
        QJsonObject s = endpointToJson({ r.server.credentials.hostName, agentPort, c.value("f").toString() });
        s["id"] = r.server.key;
        s["name"] = r.server.name;
        manifestServers.append(s);
    }
    QJsonObject manifest;
    manifest["v"] = 1;
    manifest["version"] = QDateTime::currentMSecsSinceEpoch();
    manifest["servers"] = manifestServers;
    const QByteArray manifestBytes = QJsonDocument(manifest).toJson(QJsonDocument::Compact);
    const QByteArray signature = ed25519Sign(adminSigningSeed(), manifestBytes).toBase64();

    QJsonArray agentInvites;
    for (const QJsonValue &v : storedInvites()) {
        const QJsonObject o = v.toObject();
        agentInvites.append(QJsonObject {
                { "hash",
                  QString::fromLatin1(QCryptographicHash::hash(o.value("token").toString().toUtf8(), QCryptographicHash::Sha256).toHex()) },
                { "name", o.value("name").toString() },
                { "maxDevices", o.value("maxDevices").toInt() },
                { "expires", o.value("expires").toInteger() } });
    }
    const QByteArray invitesBytes = QJsonDocument(agentInvites).toJson(QJsonDocument::Compact);

    if (reachable.isEmpty() || signature.isEmpty()) {
        finishUpload({}, failedNames);
        return;
    }

    using Phase2 = QPair<QStringList, QStringList>;
    auto *watcher = new QFutureWatcher<Phase2>(this);
    connect(watcher, &QFutureWatcher<Phase2>::finished, this, [this, watcher, failedNames]() {
        const Phase2 r = watcher->result();
        watcher->deleteLater();
        finishUpload(r.first, failedNames + r.second);
    });
    watcher->setFuture(QtConcurrent::run([reachable, manifestBytes, signature, invitesBytes]() {
        QStringList ok, failed;
        for (const AdminServer &server : reachable) {
            SshSession ssh;
            ErrorCode e = ssh.uploadFileToHost(server.credentials, manifestBytes, "/tmp/sane4ek-manifest.json");
            if (e == ErrorCode::NoError)
                e = ssh.uploadFileToHost(server.credentials, signature, "/tmp/sane4ek-manifest.sig");
            if (e == ErrorCode::NoError)
                e = ssh.uploadFileToHost(server.credentials, invitesBytes, "/tmp/sane4ek-invites.json");
            if (e == ErrorCode::NoError)
                e = ssh.runScript(server.credentials,
                                  "sudo mv -f /tmp/sane4ek-invites.json /opt/sane4ek/invites.json\n"
                                  "sudo mv -f /tmp/sane4ek-manifest.sig /opt/sane4ek/manifest.sig\n"
                                  "sudo mv -f /tmp/sane4ek-manifest.json /opt/sane4ek/manifest.json");
            (e == ErrorCode::NoError ? ok : failed).append(server.name);
        }
        return Phase2(ok, failed);
    }));
}

void Sane4ekController::finishUpload(const QStringList &okNames, const QStringList &failedNames)
{
    setBusy(false);
    emit invitesChanged(); // invite links now contain fresh certificates
    if (failedNames.isEmpty()) {
        emit operationFinished(true, tr("Uploaded to %n server(s)", "", okNames.size()));
    } else if (okNames.isEmpty()) {
        emit operationFinished(false, tr("Upload failed: %1").arg(failedNames.join(", ")));
    } else {
        emit operationFinished(false, tr("Uploaded to %1 of %2 servers. Failed: %3")
                                              .arg(okNames.size())
                                              .arg(okNames.size() + failedNames.size())
                                              .arg(failedNames.join(", ")));
    }
}

// ------------------------------------------------------------------------------------------ user

bool Sane4ekController::isInviteLink(const QString &text)
{
    return text.trimmed().startsWith(QLatin1String(invitePrefix));
}

QJsonObject Sane4ekController::clientInvite() const
{
    const QJsonObject stored = readObject("client/invite");
    if (!stored.isEmpty() || isAdmin()) {
        return stored;
    }
    // Invite embedded into this build (GitHub secret SANE4EK_DEFAULT_INVITE)
    static const QJsonObject builtIn = parseInvite(readResource(":/server_scripts/sane4ek/default_invite.txt"));
    return builtIn;
}

bool Sane4ekController::hasInvite() const
{
    return !clientInvite().value("t").toString().isEmpty();
}

bool Sane4ekController::acceptInvite(const QString &text)
{
    const QString trimmed = text.trimmed();
    if (!isInviteLink(trimmed)) {
        return false;
    }
    const QJsonObject invite = parseInvite(trimmed);
    if (invite.isEmpty()) {
        emit operationFinished(false, tr("Invalid invite"));
        return true;
    }

    const QJsonObject previous = clientInvite();
    if (!previous.isEmpty() && previous.value("k").toString() != invite.value("k").toString()) {
        removeAllManagedServers(); // invite from another administrator
        store().remove("client/endpoints");
        store().remove("client/version");
    }
    writeJson("client/invite", QJsonDocument(invite));
    emit inviteStateChanged();
    refresh();
    return true;
}

QList<Sane4ekController::Endpoint> Sane4ekController::knownEndpoints() const
{
    QList<Endpoint> result;
    QSet<QString> hosts;
    auto add = [&](const QJsonArray &arr) {
        for (const QJsonValue &v : arr) {
            const Endpoint e = endpointFromJson(v.toObject());
            if (!e.host.isEmpty() && !e.fingerprint.isEmpty() && !hosts.contains(e.host)) {
                hosts.insert(e.host);
                result.append(e);
            }
        }
    };
    add(readArray("client/endpoints"));
    add(clientInvite().value("s").toArray());
    return result;
}

void Sane4ekController::ensureDeviceKeys()
{
    if (store().value("client/deviceId").toString().isEmpty()) {
        store().setValue("client/deviceId", QUuid::createUuid().toString(QUuid::Id128));
    }
    if (store().value("client/pubKey").toString().isEmpty()) {
        QByteArray priv, pub;
        if (generateX25519(priv, pub)) {
            store().setValue("client/privKey", QString::fromLatin1(priv.toBase64()));
            store().setValue("client/pubKey", QString::fromLatin1(pub.toBase64()));
        }
    }
    store().sync();
}

void Sane4ekController::postJson(const Endpoint &endpoint, const QString &path, const QJsonObject &body,
                                 const std::function<void(int, const QJsonObject &)> &callback)
{
    QUrl url;
    url.setScheme("https");
    url.setHost(endpoint.host);
    url.setPort(endpoint.port);
    url.setPath(path);

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setTransferTimeout(15000);
    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    ssl.setPeerVerifyMode(QSslSocket::VerifyNone); // self-signed: the certificate is pinned below
    request.setSslConfiguration(ssl);

    QNetworkReply *reply = m_network->post(request, QJsonDocument(body).toJson(QJsonDocument::Compact));
    const QString expected = endpoint.fingerprint.toLower();
    auto pinned = std::make_shared<bool>(false);

    connect(reply, &QNetworkReply::encrypted, reply, [reply, expected, pinned]() {
        const QString actual = QString::fromLatin1(
                reply->sslConfiguration().peerCertificate().digest(QCryptographicHash::Sha256).toHex());
        if (actual == expected) {
            *pinned = true;
        } else {
            qWarning() << "Sane4ek: certificate mismatch for" << reply->url().host();
            reply->setProperty("sane4ekCertMismatch", true);
            reply->abort();
        }
    });
    connect(reply, &QNetworkReply::finished, this, [reply, pinned, callback]() {
        reply->deleteLater();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (!*pinned && reply->property("sane4ekCertMismatch").toBool()) {
            callback(-1, QJsonObject());
            return;
        }
        if (!*pinned || status == 0) {
            callback(0, QJsonObject());
            return;
        }
        callback(status, QJsonDocument::fromJson(reply->readAll()).object());
    });
}

void Sane4ekController::refresh()
{
    if (m_busy) {
        return;
    }
    const QJsonObject invite = clientInvite();
    if (invite.value("t").toString().isEmpty()) {
        emit operationFinished(false, isAdmin() ? tr("You are the administrator: press Upload to publish your servers")
                                                : tr("Paste the invite from your administrator first"));
        return;
    }
    const QList<Endpoint> endpoints = knownEndpoints();
    if (endpoints.isEmpty()) {
        emit operationFinished(false, tr("Invalid invite"));
        return;
    }
    setBusy(true);

    struct State
    {
        int pending = 0;
        int forbidden = 0;
        QJsonObject best;
        qint64 bestVersion = -1;
    };
    auto state = std::make_shared<State>();
    state->pending = endpoints.size();
    const QByteArray adminKey = QByteArray::fromBase64(invite.value("k").toString().toLatin1());
    const QString token = invite.value("t").toString();
    const int total = endpoints.size();

    for (const Endpoint &e : endpoints) {
        postJson(e, "/v1/manifest", QJsonObject { { "token", token } },
                 [this, state, adminKey, total](int status, const QJsonObject &reply) {
                     if (status == 403) {
                         state->forbidden++;
                     } else if (status == 200) {
                         const QByteArray bytes = QByteArray::fromBase64(reply.value("manifest").toString().toLatin1());
                         const QByteArray sig = QByteArray::fromBase64(reply.value("sig").toString().toLatin1());
                         if (ed25519Verify(adminKey, bytes, sig)) {
                             const QJsonObject m = QJsonDocument::fromJson(bytes).object();
                             const qint64 version = m.value("version").toInteger();
                             if (version > state->bestVersion) {
                                 state->bestVersion = version;
                                 state->best = m;
                             }
                         } else {
                             qWarning() << "Sane4ek: manifest signature check failed";
                         }
                     }
                     if (--state->pending > 0) {
                         return;
                     }

                     if (state->best.isEmpty()) {
                         setBusy(false);
                         if (state->forbidden == total) {
                             removeAllManagedServers();
                             emit operationFinished(false, tr("Your invite has been revoked"));
                         } else {
                             emit operationFinished(false, tr("No server is reachable. Check your internet connection"));
                         }
                         return;
                     }
                     if (state->bestVersion < store().value("client/version", 0).toLongLong()) {
                         qWarning() << "Sane4ek: servers returned an older list than we already have";
                     }
                     registerOnServers(state->best);
                 });
    }
}

void Sane4ekController::registerOnServers(const QJsonObject &manifest)
{
    ensureDeviceKeys();
    const QJsonArray servers = manifest.value("servers").toArray();

    // Every server in the list is a bootstrap endpoint for the next refresh
    writeJson("client/endpoints", QJsonDocument(servers));
    store().setValue("client/version", manifest.value("version").toInteger());

    if (servers.isEmpty()) {
        applyRegistrations(manifest, {}, {}, {});
        return;
    }

    struct State
    {
        int pending = 0;
        QStringList failed;
        QMap<QString, QString> configs;
        QSet<QString> revoked;
    };
    auto state = std::make_shared<State>();
    state->pending = servers.size();

    const QJsonObject body { { "token", clientInvite().value("t").toString() },
                             { "device", store().value("client/deviceId").toString() },
                             { "pubkey", store().value("client/pubKey").toString() },
                             { "name", QSysInfo::prettyProductName().left(40) } };

    for (const QJsonValue &v : servers) {
        const QJsonObject s = v.toObject();
        const QString key = s.value("id").toString();
        const QString name = s.value("name").toString();
        postJson(endpointFromJson(s), "/v1/register", body, [this, state, key, name, manifest](int status, const QJsonObject &reply) {
            const QString config = reply.value("config").toString();
            const QString error = reply.value("error").toString();
            if (status == 200 && !config.isEmpty()) {
                state->configs.insert(key, config);
            } else if (status == 403 && error == "device limit") {
                state->failed.append(tr("%1 (device limit of the invite reached)").arg(name));
            } else if (status == 403) {
                // The list itself was accepted, so the invite is valid: this server has not received
                // the latest invites yet (its Upload failed). Keep its old key, if any.
                state->failed.append(tr("%1 (the server does not know this invite yet, the administrator should press Upload)").arg(name));
            } else if (status == -1) {
                state->failed.append(tr("%1 (server certificate changed, the administrator should press Upload)").arg(name));
            } else if (status == 0) {
                state->failed.append(tr("%1 (no answer)").arg(name));
            } else if (error == "no awg" || error == "awg not configured") {
                state->failed.append(tr("%1 (AmneziaWG is not running on the server)").arg(name));
            } else {
                state->failed.append(QString("%1 (%2 %3)").arg(name).arg(status).arg(error));
            }
            qWarning() << "Sane4ek: register on" << name << "status" << status << error;
            if (--state->pending == 0) {
                applyRegistrations(manifest, state->configs, state->revoked, state->failed);
            }
        });
    }
}

void Sane4ekController::applyRegistrations(const QJsonObject &manifest, const QMap<QString, QString> &configs,
                                           const QSet<QString> &revokedKeys, const QStringList &failed)
{
    QJsonObject managed = readObject("client/managed");
    const QString privateKey = store().value("client/privKey").toString();
    QSet<QString> listed;
    int updated = 0;

    for (const QJsonValue &v : manifest.value("servers").toArray()) {
        const QJsonObject s = v.toObject();
        const QString key = s.value("id").toString();
        listed.insert(key);
        if (!configs.contains(key)) {
            continue;
        }

        QString text = configs.value(key);
        text.replace(privateKeyPlaceholder, privateKey);
        text.replace(hostPlaceholder, s.value("h").toString());

        const ImportController::ImportResult result = m_importController->extractConfigFromData(text);
        if (result.errorCode != ErrorCode::NoError || result.config.isEmpty()) {
            qWarning() << "Sane4ek: failed to parse config for" << s.value("name").toString();
            continue;
        }
        QJsonObject config = result.config;
        config[configKey::description] = s.value("name").toString();
        const auto kind = serverConfigUtils::configTypeFromJson(config);

        const QString localId = managed.value(key).toString();
        if (!localId.isEmpty() && m_serversRepository->indexOfServerId(localId) >= 0) {
            const auto existing = m_serversRepository->serverJsonById(localId);
            if (!existing.has_value() || existing->value(configKey::containers) != config.value(configKey::containers)
                || existing->value(configKey::description) != config.value(configKey::description)) {
                m_serversRepository->editServer(localId, config, kind);
            }
        } else if (const QString sameHostId = existingServerIdForHost(s.value("h").toString()); !sameHostId.isEmpty()) {
            // The same server is already in the list: no duplicates. A server the user manages over SSH
            // is left alone, any other entry (e.g. an old shared key) is replaced by the personal key.
            if (m_serversRepository->serverKind(sameHostId) != serverConfigUtils::ConfigType::SelfHostedAdmin) {
                m_serversRepository->editServer(sameHostId, config, kind);
                managed[key] = sameHostId;
            }
        } else {
            const QString id = m_serversRepository->addServer(QString(), config, kind);
            if (m_serversRepository->indexOfServerId(id) >= 0) {
                managed[key] = id;
            }
        }
        updated++;
    }

    // Servers removed by the administrator or revoked for this invite
    for (const QString &key : managed.keys()) {
        if (!listed.contains(key) || revokedKeys.contains(key)) {
            const QString localId = managed.value(key).toString();
            if (m_serversRepository->indexOfServerId(localId) >= 0) {
                m_serversRepository->removeServer(localId);
            }
            managed.remove(key);
        }
    }
    writeJson("client/managed", QJsonDocument(managed));

    setBusy(false);
    emit refreshFinished(updated > 0);
    if (failed.isEmpty()) {
        emit operationFinished(true, tr("Servers updated: %1").arg(updated));
    } else {
        emit operationFinished(false, tr("Servers updated: %1. No key from: %2").arg(updated).arg(failed.join(", ")));
    }
}

void Sane4ekController::removeAllManagedServers()
{
    const QJsonObject managed = readObject("client/managed");
    for (const QString &key : managed.keys()) {
        const QString localId = managed.value(key).toString();
        if (m_serversRepository->indexOfServerId(localId) >= 0) {
            m_serversRepository->removeServer(localId);
        }
    }
    store().remove("client/managed");
    store().sync();
}

// ------------------------------------------------------------------------------------------ ping

void Sane4ekController::pingAll()
{
    if (m_pingPending > 0) {
        return;
    }
    QStringList hosts;
    for (const QString &id : m_serversRepository->orderedServerIds()) {
        const auto json = m_serversRepository->serverJsonById(id);
        const QString host = json.has_value() ? json->value(configKey::hostName).toString() : QString();
        if (!host.isEmpty() && !hosts.contains(host)) {
            hosts.append(host);
        }
    }
    if (hosts.isEmpty()) {
        return;
    }

    for (const QString &host : hosts) {
        m_pings[host] = -2;
    }
    m_pingPending = hosts.size();
    emit pingsChanged();

    for (const QString &host : hosts) {
        auto *watcher = new QFutureWatcher<int>(this);
        connect(watcher, &QFutureWatcher<int>::finished, this, [this, watcher, host]() {
            m_pings[host] = watcher->result();
            watcher->deleteLater();
            m_pingPending = qMax(0, m_pingPending - 1);
            emit pingsChanged();
        });
        watcher->setFuture(QtConcurrent::run([host]() { return measurePing(host); }));
    }
}

QString Sane4ekController::existingServerIdForHost(const QString &host) const
{
    if (host.isEmpty()) {
        return QString();
    }
    for (const QString &id : m_serversRepository->orderedServerIds()) {
        const auto json = m_serversRepository->serverJsonById(id);
        if (json.has_value() && json->value(configKey::hostName).toString() == host) {
            return id;
        }
    }
    return QString();
}

void Sane4ekController::removeDuplicateServers()
{
    QJsonObject managed = readObject("client/managed");
    QMap<QString, QStringList> idsByHost;
    for (const QString &id : m_serversRepository->orderedServerIds()) {
        const auto json = m_serversRepository->serverJsonById(id);
        const QString host = json.has_value() ? json->value(configKey::hostName).toString() : QString();
        if (!host.isEmpty()) {
            idsByHost[host].append(id);
        }
    }

    QStringList managedIds;
    for (const QString &key : managed.keys()) {
        managedIds.append(managed.value(key).toString());
    }

    for (auto it = idsByHost.cbegin(); it != idsByHost.cend(); ++it) {
        const QStringList ids = it.value();
        if (ids.size() < 2) {
            continue;
        }
        // keep: a server managed over SSH, else the one with the personal Sane4ek key, else the first
        QString keep = ids.first();
        for (const QString &id : ids) {
            if (m_serversRepository->serverKind(id) == serverConfigUtils::ConfigType::SelfHostedAdmin) {
                keep = id;
                break;
            }
            if (managedIds.contains(id)) {
                keep = id;
            }
        }
        for (const QString &id : ids) {
            if (id != keep && m_serversRepository->indexOfServerId(id) >= 0) {
                qInfo() << "Sane4ek: removing duplicate server" << it.key();
                m_serversRepository->removeServer(id);
                const bool keepIsAdmin =
                        m_serversRepository->serverKind(keep) == serverConfigUtils::ConfigType::SelfHostedAdmin;
                for (const QString &key : managed.keys()) {
                    if (managed.value(key).toString() == id) {
                        if (keepIsAdmin) {
                            managed.remove(key); // never overwrite a server managed over SSH
                        } else {
                            managed[key] = keep;
                        }
                    }
                }
            }
        }
    }
    writeJson("client/managed", QJsonDocument(managed));
}

