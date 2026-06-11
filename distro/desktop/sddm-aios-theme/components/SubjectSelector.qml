import QtQuick 2.15
import QtQuick.Controls 2.15

ListView {
    id: root

    property string currentSubject: ""

    signal subjectSelected(string subjectId)

    model: ListModel {
        id: subjectModel
        ListElement {
            subjectId: "default-operator"
            displayName: "Operator"
            kind: "operator"
            clearance: "SECRET"
        }
        ListElement {
            subjectId: "default-admin"
            displayName: "Administrator"
            kind: "admin"
            clearance: "TOP_SECRET"
        }
        ListElement {
            subjectId: "default-user"
            displayName: "User"
            kind: "user"
            clearance: "CONFIDENTIAL"
        }
    }

    function loadSubjects(jsonString) {
        subjectModel.clear()
        var subjects = JSON.parse(jsonString)
        for (var i = 0; i < subjects.length; i++) {
            subjectModel.append({
                subjectId: subjects[i].id,
                displayName: subjects[i].name,
                kind: subjects[i].kind,
                clearance: subjects[i].clearance
            })
        }
    }

    delegate: ItemDelegate {
        width: root.width
        height: 56

        property bool isSelected: root.currentSubject === subjectId

        background: Rectangle {
            color: isSelected ? "#333344" : "transparent"
            radius: 4
            border.color: isSelected ? "#5566aa" : "transparent"
            border.width: isSelected ? 1 : 0
        }

        contentItem: Row {
            spacing: 12
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left
            anchors.leftMargin: 16

            Column {
                anchors.verticalCenter: parent.verticalCenter
                spacing: 4

                Text {
                    text: displayName
                    color: "#e0e0e0"
                    font.pixelSize: 14
                    font.bold: true
                    font.family: "Noto Sans"
                }

                Row {
                    spacing: 8

                    Rectangle {
                        width: 8
                        height: 8
                        radius: 4
                        color: kind === "admin" ? "#cc4444" : (kind === "operator" ? "#4488cc" : "#44aa44")
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                        text: kind.charAt(0).toUpperCase() + kind.slice(1)
                        color: "#888888"
                        font.pixelSize: 11
                        font.family: "Noto Sans"
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                        text: clearance
                        color: "#777777"
                        font.pixelSize: 10
                        font.family: "Noto Mono"
                        anchors.verticalCenter: parent.verticalCenter
                    }
                }
            }
        }

        onClicked: {
            root.currentSubject = subjectId
            root.subjectSelected(subjectId)
        }
    }
}
