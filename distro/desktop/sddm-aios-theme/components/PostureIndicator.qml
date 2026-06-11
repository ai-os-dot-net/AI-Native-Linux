import QtQuick 2.15

Rectangle {
    id: root

    property string postureName: "SECURE_DEFAULT"
    property string postureLabel: "Secure Default"
    property bool compact: false

    implicitWidth: compact ? postureText.implicitWidth + 16 : postureText.implicitWidth + 24
    implicitHeight: compact ? 22 : 28
    radius: 4
    border.width: 1

    property string _color: {
        switch (postureName) {
            case "SECURE_DEFAULT": return "#22aa22";
            case "STIG_ALIGNED":   return "#cc8800";
            case "AIRGAP_HIGH":    return "#cc2222";
            default:               return "#666666";
        }
    }

    property string _bgColor: {
        switch (postureName) {
            case "SECURE_DEFAULT": return "#1a331a";
            case "STIG_ALIGNED":   return "#332200";
            case "AIRGAP_HIGH":    return "#331a1a";
            default:               return "#1a1a1a";
        }
    }

    color: _bgColor
    border.color: _color

    Text {
        id: postureText
        anchors.centerIn: parent
        text: postureLabel
        color: _color
        font.pixelSize: compact ? 11 : 13
        font.bold: true
        font.family: "Noto Sans"
        elide: Text.ElideRight
    }
}
