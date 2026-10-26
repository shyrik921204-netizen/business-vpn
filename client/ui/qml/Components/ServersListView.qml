import QtQuick
import QtQuick.Controls

import PageEnum 1.0
import Style 1.0

import "../Controls2"

ListViewType {
    id: root

    property int selectedIndex: ServersUiController.getServerIndexById(ServersUiController.defaultServerId)

    signal serverSettingsOpened()

    leftMargin: 16
    rightMargin: 16
    bottomMargin: 16

    model: ServersModel

    Connections {
        target: ServersUiController
        function onDefaultServerIdChanged() {
            root.selectedIndex = ServersUiController.getServerIndexById(ServersUiController.defaultServerId)
        }
    }

    // Sane4ek: choosing another server while connected switches the VPN to it:
    // disconnect from the old one, then connect to the new one as soon as it is down
    property bool switchPending: false

    function switchConnection() {
        root.switchPending = true
        ConnectionController.closeConnection()
        switchFallback.restart()
    }

    function finishSwitch() {
        if (!root.switchPending) {
            return
        }
        root.switchPending = false
        switchFallback.stop()
        ConnectionController.openConnection()
    }

    Connections {
        target: ConnectionController
        function onConnectionStateChanged() {
            // pings measured while the tunnel was reconnecting are all "no answer": measure again
            if (ConnectionController.isConnected && !root.switchPending) {
                pingAfterConnect.restart()
            }
            if (root.switchPending && !ConnectionController.isConnected && !ConnectionController.isConnectionInProgress) {
                root.finishSwitch()
            }
        }
    }

    Timer {
        id: pingAfterConnect
        interval: 2000
        onTriggered: Sane4ekController.pingAll()
    }

    Timer {
        id: switchFallback
        interval: 8000
        onTriggered: root.finishSwitch()
    }

    ButtonGroup {
        id: serversRadioButtonGroup
        objectName: "serversRadioButtonGroup"
    }

    function openServerSettings(serverId) {
        ServersUiController.setProcessedServerId(serverId)

        if (ServersUiController.isServerFromApi(ServersUiController.processedServerId)) {
            if (ServersUiController.isServerCountrySelectionAvailable(ServersUiController.processedServerId)) {
                PageController.goToPage(PageEnum.PageSettingsApiAvailableCountries)
            } else {
                PageController.showBusyIndicator(true)
                let result = SubscriptionUiController.getAccountInfo(ServersUiController.processedServerId, false)
                PageController.showBusyIndicator(false)
                if (!result) {
                    return
                }

                PageController.goToPage(PageEnum.PageSettingsApiServerInfo)
            }
        } else {
            PageController.goToPage(PageEnum.PageSettingsServerInfo)
        }

        root.serverSettingsOpened()
    }

    delegate: ServerListItem {
        objectName: "serverRadioButton"

        readonly property bool subscriptionAlert: isServerFromGatewayApi && (isSubscriptionExpired || isSubscriptionExpiringSoon)
        // Sane4ek ping: ms, -1 no answer, -2 measuring, undefined not measured yet
        // while the VPN is (re)connecting no server can be reached, so no ping is shown
        readonly property var ping: ConnectionController.isConnectionInProgress ? undefined
                                                                                : Sane4ekController.pings[hostName]
        readonly property string pingText: ping === undefined ? ""
                                           : (ping === -2 ? qsTr("ping...")
                                              : (ping === -1 ? qsTr("not responding") : qsTr("%1 ms").arg(ping)))

        width: root.width - root.leftMargin - root.rightMargin

        text: name
        subtitle: subscriptionAlert
                  ? (isSubscriptionExpired ? qsTr("Subscription expired. Please renew") : qsTr("Subscription expiring soon"))
                  : (pingText === "" ? serverDescription : pingText + " · " + serverDescription)
        subtitleColor: subscriptionAlert
                       ? (isSubscriptionExpired ? AmneziaStyle.color.statusDestructive : AmneziaStyle.color.statusWarning)
                       : (ping === -1 ? AmneziaStyle.color.statusDestructive
                                      : (ping !== undefined && ping > 0 && ping < 150 ? AmneziaStyle.color.statusSuccess
                                                                                      : AmneziaStyle.color.textTertiary))
        showWarning: ServersUiController.serverHasOutdatedAwgContainer(serverId)
        showSeparator: index < root.count - 1

        checked: index === root.selectedIndex
        checkable: true

        ButtonGroup.group: serversRadioButtonGroup

        onClicked: {
            if (index === root.selectedIndex) {
                return
            }
            const wasActive = ConnectionController.isConnected || ConnectionController.isConnectionInProgress

            root.selectedIndex = index
            ServersUiController.setDefaultServerAtIndex(index)

            if (wasActive) {
                PageController.showNotificationMessage(qsTr("Switching to %1").arg(name))
                root.switchConnection()
            }
        }

        onSettingsRequested: root.openServerSettings(serverId)
        onWarningClicked: upgradeAwgContainer(serverId, name)
    }
}
