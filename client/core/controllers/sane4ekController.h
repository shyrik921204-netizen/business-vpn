#ifndef SANE4EKCONTROLLER_H
#define SANE4EKCONTROLLER_H

#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#include <functional>

#include "core/utils/commonStructs.h"

class QNetworkAccessManager;
class SecureServersRepository;
class ImportController;

// Sane4ek server distribution:
//  - admin: "Upload" installs the Sane4ek agent on every self-hosted AmneziaWG server over SSH
//           and pushes the signed server list + invites to each of them;
//  - user:  "Refresh" fetches the signed list from any reachable server and gets a personal
//           AmneziaWG key from every server in it (access by invite, no server management).
class Sane4ekController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool isAdmin READ isAdmin NOTIFY adminStateChanged)
    Q_PROPERTY(bool hasInvite READ hasInvite NOTIFY inviteStateChanged)
    Q_PROPERTY(bool busy READ isBusy NOTIFY busyChanged)
    Q_PROPERTY(QVariantList invites READ invites NOTIFY invitesChanged)
    Q_PROPERTY(QVariantMap pings READ pings NOTIFY pingsChanged)
    Q_PROPERTY(bool pingRunning READ isPingRunning NOTIFY pingsChanged)

public:
    explicit Sane4ekController(SecureServersRepository *serversRepository, ImportController *importController,
                               QObject *parent = nullptr);

    bool isAdmin() const;
    bool hasInvite() const;
    bool isBusy() const { return m_busy; }
    QVariantList invites() const;
    QVariantMap pings() const { return m_pings; }
    bool isPingRunning() const { return m_pingPending > 0; }

    static bool isInviteLink(const QString &text);

public slots:
    void upload();
    void refresh();
    // Background refresh: no messages, servers just appear or disappear
    void refreshSilently();

    bool acceptInvite(const QString &text);

    QString createInvite(const QString &name, int maxDevices, int days);
    void removeInvite(const QString &inviteId);
    QString inviteLink(const QString &inviteId) const;
    QString inviteQrCode(const QString &inviteId) const;

    // ping of every server in the list: ms, -1 = no answer, -2 = measuring
    void pingAll();
    // id of the server with the lowest measured ping, empty if none answered
    QString bestPingServerId() const;

signals:
    void adminStateChanged();
    void inviteStateChanged();
    void busyChanged();
    void invitesChanged();
    void operationFinished(bool success, const QString &message);
    void refreshFinished(bool success);
    void pingsChanged();
    void pingFinished();
    // the server selected for connection was removed by a refresh (admin removed it or the invite was revoked)
    void activeServerRemoved();

public:
    struct Endpoint
    {
        QString host;
        int port = 0;
        QString fingerprint; // hex SHA-256 of the DER certificate
    };

    struct AdminServer
    {
        QString key;
        QString name;
        amnezia::ServerCredentials credentials;
    };

    struct InstallResult
    {
        AdminServer server;
        bool ok = false;
        QString certPem;
        QString error;
    };

private:
    void setBusy(bool busy);
    QList<AdminServer> adminServers() const;

    void finishUploadPhase1(const QList<InstallResult> &results);
    void finishUpload(const QStringList &okNames, const QStringList &failedNames);

    void postJson(const Endpoint &endpoint, const QString &path, const QJsonObject &body,
                  const std::function<void(int status, const QJsonObject &reply)> &callback);
    void registerOnServers(const QJsonObject &manifest);
    void applyRegistrations(const QJsonObject &manifest, const QMap<QString, QString> &configs,
                            const QSet<QString> &revokedKeys, const QStringList &failed);
    void removeAllManagedServers();

    QByteArray adminSigningSeed();
    QJsonArray storedInvites() const;
    void storeInvites(const QJsonArray &invites);
    QJsonObject clientInvite() const;
    QList<Endpoint> knownEndpoints() const;
    void ensureDeviceKeys();

    SecureServersRepository *m_serversRepository;
    ImportController *m_importController;
    QNetworkAccessManager *m_network;
    bool m_busy = false;
    bool m_silent = false;
    qint64 m_lastRefreshMs = 0;
    void reportRefresh(bool success, const QString &message);
    QVariantMap m_pings;
    int m_pingPending = 0;
    QString existingServerIdForHost(const QString &host) const;
    void removeDuplicateServers();
};

#endif // SANE4EKCONTROLLER_H
