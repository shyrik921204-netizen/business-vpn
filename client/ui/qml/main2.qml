import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

import PageEnum 1.0
import Style 1.0

import "Config"
import "Controls2"
import "Components"
import "Pages2"

Window  {
    id: root
    objectName: "mainWindow"

    Connections {
        target: Qt.application
        function onStateChanged() {
            if (Qt.platform.os === "android") {
                if (Qt.application.state === Qt.ApplicationActive) {
                    root.visible = true
                    refreshTimer.restart()
                }
            }
        }
    }

    // Hide the window immediately when Android Activity.onPause() fires so that
    // Qt's render loop stops before the EGL surface is disconnected.  This
    // prevents "QRhiGles2: Failed to make context current" and the resulting
    // black screen that appears after swiping home and returning.
    Connections {
        target: SettingsController
        function onActivityPaused() {
            if (Qt.platform.os === "android") root.visible = false
        }
        function onActivityResumed() {
            if (Qt.platform.os === "android") root.visible = true
        }
    }

    Timer {
        id: refreshTimer
        interval: 150
        repeat: false
        onTriggered: {
            if (Qt.platform.os === "android" && PageController.isEdgeToEdgeEnabled()) {
                console.log("QML: Application resumed with edge-to-edge")
            }
        }
    }

    visible: !GC.isDesktop()
    width: GC.screenWidth
    height: GC.screenHeight
    minimumWidth: GC.isDesktop() ? 360 : 0
    minimumHeight: GC.isDesktop() ? 640 : 0
    maximumWidth: 600
    maximumHeight: 800

    flags: Qt.platform.os === "ios" ? (Qt.Window | Qt.ExpandedClientAreaHint) : Qt.Window

    color: AmneziaStyle.color.bgBase

    onClosing: function(close) {
        close.accepted = false
        PageController.closeWindow()
    }

    onActiveFocusItemChanged: {
        if (activeFocusItem === contentItem) {
            pageStart.forceActiveFocus()
        }
    }

    onSceneGraphError: function(error, message) {
        // Prevent qFatal crash on Android when EGL context is lost
        console.warn("Scene graph error:", error, message)
    }

    title: "Sane4ek"

    Loader {
        active: Qt.platform.os === "android"
        source: Qt.platform.os === "android" ? "Components/GamepadLoader.qml" : ""
    }

    Connections {
        objectName: "pageControllerConnections"

        target: PageController

        function onRaiseMainWindow() {
            root.show()
            root.raise()
            root.requestActivate()
        }

        function onHideMainWindow() {
            root.hide()
        }

        function onShowErrorMessage(errorMessage) {
            popupErrorMessage.show(errorMessage)
        }

        function onShowNotificationMessage(message) {
            popupNotificationMessage.show(message)
        }

        function onShowPassphraseRequestDrawer() {
            privateKeyPassphraseDrawer.open()
        }

        function onGoToPageSettingsBackup() {
            PageController.goToPage(PageEnum.PageSettingsBackup)
        }

        function onShowBusyIndicator(visible) {
            busyIndicator.visible = visible
            PageController.disableControls(visible)
        }

    }

    Connections {
        objectName: "settingsControllerConnections"

        target: SettingsController

        function onChangeSettingsFinished(finishedMessage) {
            PageController.showNotificationMessage(finishedMessage)
        }
    }

    PageStart {
        id: pageStart
        objectName: "pageStart"
        width: root.width
        height: root.height

        focus: true
    }

    SnackbarType {
        id: popupNotificationMessage
        objectName: "popupNotificationMessage"

        bottomOffset: Math.max(PageController.safeAreaBottomMargin, pageStart.tabBarHeight - 4)

        duration: 3000
    }

    SnackbarType {
        id: popupErrorMessage
        objectName: "popupErrorMessage"

        bottomOffset: Math.max(PageController.safeAreaBottomMargin, pageStart.tabBarHeight - 4)

        variant: SnackbarType.Destructive
        closable: true
        duration: 0
    }

    Item {
        objectName: "captchaDialogItem"

        anchors.fill: parent

        CaptchaDialogType {
            id: captchaDialog

            onCaptchaSolved: function(captchaId, solution) {
                PageController.showBusyIndicator(true)
                Qt.callLater(function() {
                    SubscriptionUiController.onCaptchaSolved(captchaId, solution)
                })
            }

            onRefreshCaptchaRequested: function() {
                SubscriptionUiController.onRefreshCaptchaRequested()
            }
        }
    }

    SheetType {
        id: privateKeyPassphraseDrawer

        property bool isCloseByUser: false

        expandedHeight: windowHeight * 0.35 + PageController.safeAreaBottomMargin + PageController.imeHeight

        onAboutToShow: {
            PageController.showBusyIndicator(false)
        }

        onOpened: {
            passphrase.textField.text = ""
            passphrase.textField.forceActiveFocus()
        }

        onAboutToHide: {
            if (privateKeyPassphraseDrawer.isCloseByUser === false) {
                privateKeyPassphraseDrawer.isCloseByUser = true
                PageController.passphraseRequestDrawerClosed("")
            }

            if (passphrase.textField.text !== "") {
                PageController.showBusyIndicator(true)
            }
        }

        ColumnLayout {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.topMargin: 16
            anchors.leftMargin: 16
            anchors.rightMargin: 16

            TextFieldType {
                id: passphrase

                Layout.fillWidth: true
                headerText: qsTr("Private key passphrase")
                passwordToggle: true
            }

            ButtonType {
                id: saveButton
                variant: ButtonType.Secondary

                Layout.fillWidth: true

                text: qsTr("Save")

                onClicked: {
                    privateKeyPassphraseDrawer.isCloseByUser = true
                    privateKeyPassphraseDrawer.close()
                    PageController.passphraseRequestDrawerClosed(passphrase.textField.text)
                }
            }
        }
    }

    QuestionDrawer {
        id: questionDrawer
    }

    SubscriptionExpiredDrawer {
        id: subscriptionExpiredDrawer
    }

    // Sane4ek: the server in use disappeared after a background refresh (removed by the administrator
    // or the invite expired): disconnect, measure pings over the normal network (VPN is off by then)
    // and connect to the server with the best ping
    QtObject {
        id: sane4ekAutoSwitch
        property bool waitDisconnect: false
        property bool waitPing: false

        function start() {
            if (ConnectionController.isConnected || ConnectionController.isConnectionInProgress) {
                waitDisconnect = true
                ConnectionController.closeConnection()
                sane4ekAutoSwitchFallback.restart()
            }
        }

        function measure() {
            if (!waitDisconnect) {
                return
            }
            waitDisconnect = false
            sane4ekAutoSwitchFallback.stop()
            waitPing = true
            Sane4ekController.pingAll()
        }

        function connectBest() {
            if (!waitPing) {
                return
            }
            waitPing = false
            var serverId = Sane4ekController.bestPingServerId()
            if (serverId === "") {
                return
            }
            ServersUiController.setDefaultServerAtIndex(ServersUiController.getServerIndexById(serverId))
            ConnectionController.openConnection()
        }
    }

    Timer {
        id: sane4ekAutoSwitchFallback
        interval: 8000
        onTriggered: sane4ekAutoSwitch.measure()
    }

    Connections {
        target: ConnectionController
        function onConnectionStateChanged() {
            if (sane4ekAutoSwitch.waitDisconnect && !ConnectionController.isConnected
                    && !ConnectionController.isConnectionInProgress) {
                sane4ekAutoSwitch.measure()
            }
        }
    }

    Connections {
        target: Sane4ekController

        function onActiveServerRemoved() {
            sane4ekAutoSwitch.start()
        }

        function onPingFinished() {
            sane4ekAutoSwitch.connectBest()
        }
    }

    Connections {
        target: Sane4ekController

        function onOperationFinished(success, message) {
            if (success) {
                PageController.showNotificationMessage(message)
            } else {
                PageController.showErrorMessage(message)
            }
        }

        function onRefreshFinished(success) {
            if (success) {
                PageController.goToPageHome()
            }
        }
    }

    Connections {
        target: PageController

        function onUnsupportedConnectDrawerRequested() {
            root.showUnsupportedConnectDrawer()
        }
    }

    Connections {
        target: SubscriptionUiController

        function onSubscriptionExpiredOnServer() {
            subscriptionExpiredDrawer.open()
        }

        function onCaptchaRequired(captchaId, captchaImageBase64, hint) {
            if (captchaDialog.opened) {
                PageController.showBusyIndicator(false)
            }
            captchaDialog.captchaId = captchaId
            captchaDialog.captchaImageBase64 = captchaImageBase64
            captchaDialog.hint = hint
            captchaDialog.open()
        }

        function onCaptchaFlowDismissRequested() {
            PageController.showBusyIndicator(false)
            captchaDialog.close()
        }

        function onErrorOccurred(error) {
            if (captchaDialog.opened) {
                PageController.showBusyIndicator(false)
            }
        }
    }

    Connections {
        target: SubscriptionUiController

        function onRenewalLinkReceived(url) {
            Qt.openUrlExternally(url)
        }
    }

    Item {
        objectName: "busyIndicatorItem"

        anchors.fill: parent

        LoadingOverlayType {
            id: busyIndicator
            anchors.centerIn: parent
            z: 1

            blurSource: pageStart
        }
    }

    function showUnsupportedConnectDrawer() {
        let headerText = qsTr("This subscription format is no longer supported")
        let descriptionText = qsTr("This legacy Amnezia subscription type can no longer be used to connect in this application version.\nRemove the server from the app to continue.")
        let yesButtonText = qsTr("Continue")
        let noButtonText = qsTr("Cancel")

        let yesButtonFunction = function() {
            if (ConnectionController.isConnected) {
                PageController.showNotificationMessage(qsTr("Cannot remove server during active connection"))
                return
            }

            PageController.showBusyIndicator(true)
            InstallController.removeServer(ServersUiController.defaultServerId)
            PageController.showBusyIndicator(false)
        }
        let noButtonFunction = function() {
        }

        showQuestionDrawer(headerText, descriptionText, yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
    }

    // Sane4ek: replace the outdated AmneziaWG container of one server with AmneziaWG 3.1
    function upgradeAwgContainer(serverId, serverName) {
        var headerText = qsTr("Update AmneziaWG on \"%1\" to 3.1?").arg(serverName)
        var descriptionText = qsTr("The old container is removed and AmneziaWG 3.1 is installed on the same port. It takes 2-5 minutes. Old keys of this server stop working: Sane4ek users get new ones by pressing Refresh, keys shared in other ways have to be shared again.")
        showQuestionDrawer(headerText, descriptionText, qsTr("Update"), qsTr("Cancel"), function() {
            if (ConnectionController.isConnected || ConnectionController.isConnectionInProgress) {
                PageController.showErrorMessage(qsTr("Disconnect the VPN before updating the server"))
                return
            }
            PageController.showBusyIndicator(true)
            InstallController.upgradeAwgContainer(serverId)
            PageController.showBusyIndicator(false)
        }, function() {})
    }

    Connections {
        target: InstallController

        function onUpgradeAwgFinished(finishedMessage) {
            PageController.showNotificationMessage(finishedMessage)
        }
    }

    function showQuestionDrawer(headerText, descriptionText, yesButtonText, noButtonText, yesButtonFunction, noButtonFunction) {
        questionDrawer.headerText = headerText
        questionDrawer.descriptionText = descriptionText
        questionDrawer.yesButtonText = yesButtonText
        questionDrawer.noButtonText = noButtonText

        questionDrawer.yesButtonFunction = function() {
            questionDrawer.close()
            if (yesButtonFunction && typeof yesButtonFunction === "function") {
                yesButtonFunction()
            }
        }
        questionDrawer.noButtonFunction = function() {
            questionDrawer.close()
            if (noButtonFunction && typeof noButtonFunction === "function") {
                noButtonFunction()
            }
        }
        questionDrawer.open()
    }

    FileDialog {
        id: mainFileDialog
        objectName: "mainFileDialog"

        property bool isSaveMode: false

        fileMode: isSaveMode ? FileDialog.SaveFile : FileDialog.OpenFile

        onAccepted: SystemController.fileDialogClosed(true)
        onRejected: SystemController.fileDialogClosed(false)
    }

}
