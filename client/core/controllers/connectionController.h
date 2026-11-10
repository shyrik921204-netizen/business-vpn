#ifndef CONNECTIONCONTROLLER_H
#define CONNECTIONCONTROLLER_H

#include <QObject>
#include <QTimer>
#include <QJsonObject>
#include <QPair>
#include <memory>

#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/protocols/vpnProtocol.h"
#include "vpnConnection.h"

using namespace amnezia;

class ConnectionController : public QObject
{
    Q_OBJECT

public:
    explicit ConnectionController(SecureServersRepository* serversRepository,
                                 SecureAppSettingsRepository* appSettingsRepository,
                                 VpnConnection* vpnConnection,
                                 QObject* parent = nullptr);
    ~ConnectionController() = default;

    ErrorCode prepareConnection(const QString &serverId,
                               QJsonObject& vpnConfiguration,
                               DockerContainer& container);

    ErrorCode isConnectionSupported(const QString &serverId) const;

    ErrorCode openConnection(const QString &serverId);

    void closeConnection();

#ifdef Q_OS_ANDROID
    void restoreConnection();
#endif

    void onKillSwitchModeChanged(bool enabled);

    ErrorCode lastConnectionError() const;

    bool isConnected() const;
    void setConnectionState(Vpn::ConnectionState state);

    QJsonObject createConnectionConfiguration(const QPair<QString, QString> &dns,
                                             bool isApiConfig,
                                             const QString &hostName,
                                             const QString &description,
                                             int configVersion,
                                             const ContainerConfig &containerConfig,
                                             DockerContainer container);

    bool isServiceReady() const;

    bool isContainerSupported(DockerContainer container) const;

signals:
    void connectionStateChanged(Vpn::ConnectionState state);
    void openConnectionRequested(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration);
    void closeConnectionRequested();
    void killSwitchModeChangedRequested(bool enabled);

#ifdef Q_OS_ANDROID
    void restoreConnectionRequested();
#endif

private:
    ErrorCode defaultContainerForServer(const QString &serverId, DockerContainer &container) const;

    SecureServersRepository* m_serversRepository;
    SecureAppSettingsRepository* m_appSettingsRepository;
    VpnConnection* m_vpnConnection;

    // Sane4ek: when AmneziaWG is blocked (no handshake / nothing comes back) on a server that also
    // has VLESS + Reality, the server is switched to Reality and connected again
    void startProtocolProbe(const QString &serverId, DockerContainer container);
    void stopProtocolProbe();
    void onProtocolProbeTimeout();
    bool switchServerToXray(const QString &serverId);

    QTimer *m_protocolProbe = nullptr;
    QString m_probeServerId;
    bool m_probeRxSeen = false;
    bool m_probeTxSeen = false;
    QString m_reconnectServerId;
    Vpn::ConnectionState m_lastState = Vpn::ConnectionState::Disconnected;
};

#endif
