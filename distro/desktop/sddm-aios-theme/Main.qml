import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import SddmComponents 2.0

import "components"

Rectangle {
    id: root
    width: Screen.width
    height: Screen.height

    color: "#0d0d1a"

    property string posture: "SECURE_DEFAULT"

    Timer {
        id: postureTimer
        interval: 1000
        repeat: true
        running: true
        onTriggered: {
            var req = new XMLHttpRequest()
            req.open("GET", "file:///etc/aios/time-posture", false)
            try {
                req.send()
                if (req.status === 200 || req.status === 0) {
                    var text = req.responseText.trim()
                    if (text.length > 0 && text.length < 64) {
                        root.posture = text
                    }
                }
            } catch (e) {
            }
        }
    }

    function postureLabel() {
        switch (root.posture) {
            case "SECURE_DEFAULT": return "Secure Default"
            case "STIG_ALIGNED":   return "STIG Aligned"
            case "AIRGAP_HIGH":    return "Airgap High"
            default:               return root.posture
        }
    }

    Item {
        id: backgroundOverlay
        anchors.fill: parent

        Rectangle {
            anchors.fill: parent
            gradient: Gradient {
                GradientStop { position: 0.0; color: "#0d0d1a" }
                GradientStop { position: 0.4; color: "#111128" }
                GradientStop { position: 0.7; color: "#0d0d1a" }
                GradientStop { position: 1.0; color: "#080812" }
            }
        }

        Rectangle {
            width: parent.width
            height: 2
            anchors.bottom: parent.verticalCenter
            anchors.bottomMargin: 120
            color: "#223344"
            opacity: 0.3
        }

        Rectangle {
            width: parent.width
            height: 1
            anchors.top: parent.verticalCenter
            anchors.topMargin: 120
            color: "#223344"
            opacity: 0.15
        }
    }

    ColumnLayout {
        id: mainLayout
        anchors.centerIn: parent
        width: Math.min(520, parent.width - 80)
        spacing: 0

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 16
        }

        Rectangle {
            Layout.alignment: Qt.AlignHCenter
            width: 64
            height: 64
            radius: 16
            color: "#1a1a3a"
            border.color: "#334466"
            border.width: 1

            Text {
                anchors.centerIn: parent
                text: "AI"
                color: "#88aacc"
                font.pixelSize: 28
                font.bold: true
                font.family: "Noto Sans"
            }
        }

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 16
        }

        Text {
            Layout.alignment: Qt.AlignHCenter
            text: "AI-OS.NET"
            color: "#ccddee"
            font.pixelSize: 28
            font.bold: true
            font.family: "Noto Sans"
            font.letterSpacing: 4
        }

        Text {
            Layout.alignment: Qt.AlignHCenter
            text: "AI-Native Linux Desktop"
            color: "#556688"
            font.pixelSize: 13
            font.family: "Noto Sans"
            font.letterSpacing: 2
        }

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 8
        }

        Text {
            id: hostnameText
            Layout.alignment: Qt.AlignHCenter
            text: ""
            color: "#334466"
            font.pixelSize: 11
            font.family: "Noto Mono"

            Timer {
                interval: 2000
                running: true
                repeat: false
                onTriggered: {
                    var req = new XMLHttpRequest()
                    req.open("GET", "file:///etc/hostname", false)
                    try {
                        req.send()
                        if (req.status === 200 || req.status === 0) {
                            hostnameText.text = req.responseText.trim()
                        }
                    } catch (e) {
                        hostnameText.text = "aios"
                    }
                }
            }
        }

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 28
        }

        PostureIndicator {
            Layout.alignment: Qt.AlignHCenter
            postureName: root.posture
            postureLabel: root.postureLabel()
        }

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 28
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 12

            Text {
                text: "Login"
                color: "#778899"
                font.pixelSize: 11
                font.family: "Noto Sans"
                font.bold: true
                font.letterSpacing: 3
                Layout.alignment: Qt.AlignLeft
            }

            TextBox {
                id: usernameField
                Layout.fillWidth: true
                Layout.preferredHeight: 44
                font.pixelSize: 15
                font.family: "Noto Sans"
                color: "#e0e0e0"
                borderColor: "#334466"
                focusColor: "#4466aa"
                hoverColor: "#445577"
                textColor: "#e0e0e0"
                placeholderText: "Username"
                placeholderColor: "#445566"

                Keys.onReturnPressed: passwordField.forceActiveFocus()
            }

            PasswordBox {
                id: passwordField
                Layout.fillWidth: true
                Layout.preferredHeight: 44
                font.pixelSize: 15
                font.family: "Noto Sans"
                color: "#e0e0e0"
                borderColor: "#334466"
                focusColor: "#4466aa"
                hoverColor: "#445577"
                textColor: "#e0e0e0"
                placeholderText: "Password"
                placeholderColor: "#445566"

                Keys.onReturnPressed: loginButton.clicked()
            }
        }

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 8
        }

        Button {
            id: loginButton
            Layout.fillWidth: true
            Layout.preferredHeight: 44

            background: Rectangle {
                radius: 6
                color: loginButton.down ? "#335577" : (loginButton.hovered ? "#446688" : "#334466")
                border.color: loginButton.down ? "#5588aa" : "#4466aa"
                border.width: 1
            }

            contentItem: Text {
                text: "Authenticate"
                color: "#ccddee"
                font.pixelSize: 15
                font.bold: true
                font.family: "Noto Sans"
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
            }

            onClicked: sddm.login(usernameField.text, passwordField.text, 0)
        }
    }

    Item {
        id: bottomBar
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: 36

        Rectangle {
            anchors.fill: parent
            color: "#080812"
            opacity: 0.8
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16
            spacing: 12

            Item { Layout.fillWidth: true }

            ComboBox {
                id: keyboardSelector
                Layout.preferredWidth: 120
                model: keyboard.layouts
                currentIndex: keyboard.currentLayout
                onCurrentIndexChanged: keyboard.currentLayout = currentIndex

                background: Rectangle {
                    color: "#111122"
                    border.color: "#334466"
                    radius: 4
                }
                contentItem: Text {
                    color: "#8899aa"
                    font.pixelSize: 11
                    font.family: "Noto Sans"
                    verticalAlignment: Text.AlignVCenter
                    leftPadding: 8
                    text: keyboardSelector.displayText
                }

                delegate: ItemDelegate {
                    width: keyboardSelector.width
                    contentItem: Text {
                        text: modelData
                        color: "#ccddee"
                        font.pixelSize: 11
                        font.family: "Noto Sans"
                        verticalAlignment: Text.AlignVCenter
                    }
                    background: Rectangle {
                        color: highlighted ? "#334466" : "transparent"
                    }
                }
            }
        }
    }

    function get_posture_color() {
        switch (root.posture) {
            case "STIG_ALIGNED": return "#cc8800"
            case "AIRGAP_HIGH":  return "#cc2222"
            default:             return "#22aa22"
        }
    }
}
