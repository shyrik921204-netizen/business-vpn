import QtQuick
import QtQuick.Shapes

// Sane4ek: animated smiley that puts on sunglasses (shown when VPN is connected)
Item {
    id: root

    property bool active: false

    implicitWidth: 56
    implicitHeight: 56

    visible: active || face.scale > 0.01

    onActiveChanged: active ? play() : hide()
    Component.onCompleted: if (active) play()

    function play() {
        hideAnim.stop()
        face.scale = 0
        glasses.y = -root.height * 0.6
        glasses.opacity = 0
        eyes.opacity = 1
        smile.scale = 0.75
        glint.x = 0
        glint.opacity = 0
        showAnim.restart()
    }

    function hide() {
        showAnim.stop()
        hideAnim.restart()
    }

    readonly property real u: width / 56   // design grid unit

    Item {
        id: face
        width: root.width
        height: root.height
        transformOrigin: Item.Center
        scale: 0

        // head
        Rectangle {
            anchors.fill: parent
            radius: width / 2
            gradient: Gradient {
                GradientStop { position: 0.0; color: "#FFE066" }
                GradientStop { position: 1.0; color: "#FFB627" }
            }
            border.color: "#E09600"
            border.width: Math.max(1, root.u)
        }

        // eyes (covered by glasses later)
        Item {
            id: eyes
            anchors.fill: parent
            Rectangle { x: 16 * root.u; y: 17 * root.u; width: 6 * root.u; height: 8 * root.u; radius: width / 2; color: "#5A3A00" }
            Rectangle { x: 34 * root.u; y: 17 * root.u; width: 6 * root.u; height: 8 * root.u; radius: width / 2; color: "#5A3A00" }
        }

        // smile
        Item {
            id: smile
            anchors.fill: parent
            transformOrigin: Item.Center
            scale: 0.75

            Shape {
                anchors.fill: parent
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    fillColor: "transparent"
                    strokeColor: "#5A3A00"
                    strokeWidth: 3.2 * root.u
                    capStyle: ShapePath.RoundCap
                    PathAngleArc {
                        centerX: 28 * root.u
                        centerY: 30 * root.u
                        radiusX: 14 * root.u
                        radiusY: 12 * root.u
                        startAngle: 25
                        sweepAngle: 130
                    }
                }
            }
        }

        // sunglasses
        Item {
            id: glasses
            x: 0
            y: -root.height * 0.6
            width: root.width
            height: 16 * root.u
            opacity: 0

            Rectangle { x: 2 * root.u;  y: 6 * root.u; width: 8 * root.u;  height: 2.2 * root.u; color: "#1B1B1F" }   // left arm
            Rectangle { x: 46 * root.u; y: 6 * root.u; width: 8 * root.u;  height: 2.2 * root.u; color: "#1B1B1F" }   // right arm
            Rectangle { x: 25 * root.u; y: 5 * root.u; width: 6 * root.u;  height: 2.6 * root.u; color: "#1B1B1F" }   // bridge

            Rectangle {
                id: lensL
                x: 8 * root.u; y: 3 * root.u; width: 18 * root.u; height: 12 * root.u
                radius: 3 * root.u
                color: "#1B1B1F"
                bottomLeftRadius: 7 * root.u
                bottomRightRadius: 7 * root.u
                clip: true
                Rectangle { id: glint; x: 0; y: -4 * root.u; width: 4 * root.u; height: 22 * root.u; rotation: 30; color: "#FFFFFF"; opacity: 0 }
            }
            Rectangle {
                x: 30 * root.u; y: 3 * root.u; width: 18 * root.u; height: 12 * root.u
                radius: 3 * root.u
                color: "#1B1B1F"
                bottomLeftRadius: 7 * root.u
                bottomRightRadius: 7 * root.u
            }
        }
    }

    SequentialAnimation {
        id: showAnim
        // pop in
        NumberAnimation { target: face; property: "scale"; from: 0; to: 1; duration: 320; easing.type: Easing.OutBack }
        PauseAnimation { duration: 150 }
        // sunglasses drop onto the eyes
        ParallelAnimation {
            NumberAnimation { target: glasses; property: "opacity"; from: 0; to: 1; duration: 150 }
            NumberAnimation { target: glasses; property: "y"; to: 13 * root.u; duration: 550; easing.type: Easing.OutBounce }
        }
        ParallelAnimation {
            NumberAnimation { target: eyes; property: "opacity"; to: 0; duration: 80 }
            NumberAnimation { target: smile; property: "scale"; to: 1.12; duration: 260; easing.type: Easing.OutBack }
        }
        // glint across the left lens
        PauseAnimation { duration: 120 }
        ParallelAnimation {
            NumberAnimation { target: glint; property: "opacity"; from: 0; to: 0.8; duration: 120 }
            NumberAnimation { target: glint; property: "x"; from: 0; to: 18 * root.u; duration: 380; easing.type: Easing.InOutQuad }
        }
        NumberAnimation { target: glint; property: "opacity"; to: 0; duration: 120 }
    }

    NumberAnimation {
        id: hideAnim
        target: face; property: "scale"; to: 0; duration: 180; easing.type: Easing.InBack
    }
}
