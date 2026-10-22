import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"
import "../Components"

// Sane4ek: invites for users. A user pastes or scans the invite and then
// gets every server of the administrator with a personal key via "Refresh".
PageType {
    id: root

    property string shownInviteId: ""
    property string shownInviteName: ""

    function showInvite(inviteId, name) {
        root.shownInviteId = inviteId
        root.shownInviteName = name
        qrImage.source = Sane4ekController.inviteQrCode(inviteId)
        inviteSheet.open()
    }

    Connections {
        target: Sane4ekController

        function onInvitesChanged() {
            if (root.shownInviteId !== "") {
                qrImage.source = Sane4ekController.inviteQrCode(root.shownInviteId)
            }
        }
    }

    FlickableType {
        id: flickable

        anchors.fill: parent
        contentHeight: content.implicitHeight + 24

        ColumnLayout {
            id: content

            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right

            spacing: 0

            NavigationBarType {
                Layout.fillWidth: true

                title: qsTr("Invites")
                description: qsTr("Give an invite to a person. After pressing Refresh they get all your servers with a personal key, without access to server management. Deleting an invite disables its keys on all servers.")
            }

            TextFieldType {
                id: nameField

                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                headerText: qsTr("Name, e.g. Vasya")
                textField.maximumLength: 40
            }

            TextFieldType {
                id: devicesField

                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                headerText: qsTr("Device limit (1-20, empty - no limit)")
                textField.inputMethodHints: Qt.ImhDigitsOnly
                textField.validator: IntValidator { bottom: 0; top: 20 }
            }

            ButtonType {
                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                enabled: !Sane4ekController.busy
                text: Sane4ekController.busy ? qsTr("Uploading to servers...") : qsTr("Create invite")

                onClicked: {
                    var limit = parseInt(devicesField.textField.text)
                    var id = Sane4ekController.createInvite(nameField.textField.text, isNaN(limit) ? 0 : limit)
                    if (id !== "") {
                        var name = nameField.textField.text
                        nameField.textField.text = ""
                        devicesField.textField.text = ""
                        root.showInvite(id, name)
                    }
                }
            }

            SmallTextType {
                Layout.fillWidth: true
                Layout.topMargin: 32
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                visible: Sane4ekController.invites.length > 0
                text: qsTr("Created invites")
            }

            Repeater {
                model: Sane4ekController.invites

                delegate: ListItemType {
                    Layout.fillWidth: true
                    Layout.leftMargin: 16
                    Layout.rightMargin: 16

                    text: modelData.name
                    subtitle: modelData.created + (modelData.maxDevices > 0
                                                   ? " · " + qsTr("up to %1 devices").arg(modelData.maxDevices) : "")

                    onClicked: root.showInvite(modelData.id, modelData.name)

                    IconButtonType {
                        size: IconButtonType.Small
                        icon.source: "qrc:/images/controls/trash.svg"
                        enabled: !Sane4ekController.busy

                        onClicked: {
                            var inviteId = modelData.id
                            var headerText = qsTr("Delete invite \"%1\"?").arg(modelData.name)
                            var descriptionText = qsTr("The keys of this invite will stop working on all servers")
                            showQuestionDrawer(headerText, descriptionText, qsTr("Delete"), qsTr("Cancel"),
                                               function() { Sane4ekController.removeInvite(inviteId) },
                                               function() {})
                        }
                    }
                }
            }
        }
    }

    SheetType {
        id: inviteSheet

        expandedHeight: windowHeight * 0.9
        parent: root

        FlickableType {
            anchors.fill: parent
            contentHeight: sheetContent.implicitHeight + 32

            ColumnLayout {
                id: sheetContent

                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 16
                anchors.rightMargin: 16

                spacing: 16

                H2TextType {
                    Layout.fillWidth: true
                    Layout.topMargin: 8
                    text: qsTr("Invite: %1").arg(root.shownInviteName)
                }

                SmallTextType {
                    Layout.fillWidth: true
                    text: qsTr("Scan the QR code in Sane4ek (+ → QR code) or paste the link into the key field")
                }

                Image {
                    id: qrImage

                    Layout.fillWidth: true
                    Layout.maximumWidth: 360
                    Layout.preferredHeight: width
                    Layout.alignment: Qt.AlignHCenter

                    fillMode: Image.PreserveAspectFit
                    smooth: false

                    Rectangle {
                        anchors.fill: parent
                        z: -1
                        color: "white"
                        radius: 8
                    }
                }

                SmallTextType {
                    Layout.fillWidth: true

                    visible: qrImage.source == ""
                    color: AmneziaStyle.color.textAccent
                    text: Sane4ekController.busy ? qsTr("Uploading to servers...")
                                                 : qsTr("Servers are not ready. Press Upload on the home screen and check SSH access")
                }

                ButtonType {
                    Layout.fillWidth: true

                    enabled: qrImage.source != ""
                    text: qsTr("Copy invite link")

                    onClicked: {
                        GC.copyToClipBoard(Sane4ekController.inviteLink(root.shownInviteId))
                        PageController.showNotificationMessage(qsTr("Copied"))
                    }
                }

                ButtonType {
                    Layout.fillWidth: true

                    variant: ButtonType.Secondary
                    text: qsTr("Close")

                    onClicked: inviteSheet.close()
                }
            }
        }
    }
}
