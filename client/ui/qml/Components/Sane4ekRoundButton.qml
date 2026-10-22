import QtQuick
import QtQuick.Controls
import QtQuick.Controls.impl

import Style 1.0

// Sane4ek: small round icon button for the home screen (upload / refresh)
Button {
    id: root

    property bool busy: false

    implicitWidth: 64
    implicitHeight: 64

    padding: 0
    hoverEnabled: true
    opacity: root.enabled || root.busy ? 1 : 0.5

    onBusyChanged: if (!busy) iconImage.rotation = 0

    background: Rectangle {
        radius: width / 2
        color: root.down ? AmneziaStyle.color.bgStateLayerPressed
                         : (root.hovered ? AmneziaStyle.color.bgStateLayer : AmneziaStyle.color.transparent)
        border.width: 2
        border.color: root.busy ? AmneziaStyle.color.accentLight : AmneziaStyle.color.borderEmphasis

        Behavior on border.color {
            ColorAnimation { duration: 150 }
        }
    }

    contentItem: Item {
        IconImage {
            id: iconImage

            anchors.centerIn: parent
            width: 26
            height: 26

            source: root.icon.source
            color: root.busy ? AmneziaStyle.color.textAccent : AmneziaStyle.color.iconDefault

            RotationAnimator on rotation {
                running: root.busy
                from: 0
                to: 360
                duration: 900
                loops: Animation.Infinite
            }
        }
    }

    HoverHandler {
        cursorShape: Qt.PointingHandCursor
    }
}
