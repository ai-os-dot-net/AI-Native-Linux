// The AIOS shared component library, materialised as QML for the KDE renderer.
// Every colour binds the generated AiosTokens singleton (aios-design-tokens
// to_qml_properties) — the SAME tokens the Web renderer emits as CSS. This is
// the KDE half of "an approval looks like an approval, everywhere".
import QtQuick
import aios.generated

Window {
    id: win
    visible: true
    width: 900; height: 900
    color: AiosTokens.colorSurface

    // [tag, label, colorProp, outline, italic, bold, elevated, block] — one row
    // per ComponentRecipe. Distinction axes drive the QML the same way they
    // drive the CSS: hue=colour, outline=border, typography=italic, elevation.
    ListModel { id: comps
        ListElement { tag:"🛡"; label:"System integrity verified · SELinux enforcing"; col:"colorTrustVerified"; outline:false; italic:false; bold:true; elev:false; block:true }
        ListElement { tag:"🔒"; label:"RECOVERY MODE — cognition offline"; col:"colorRecovery"; outline:true; italic:true; bold:true; elev:true; block:true }
        ListElement { tag:"◆"; label:"AI agent"; col:"colorActionAi"; outline:true; italic:true; bold:true; elev:false; block:false }
        ListElement { tag:"◉"; label:"operator"; col:"colorActionHuman"; outline:true; italic:false; bold:true; elev:false; block:false }
        ListElement { tag:"✓"; label:"verified"; col:"colorTrustVerified"; outline:false; italic:false; bold:true; elev:false; block:false }
        ListElement { tag:"⛓"; label:"ev:9f2a…c1 · FOREVER"; col:"colorEvidencePermanent"; outline:false; italic:false; bold:true; elev:true; block:false }
        ListElement { tag:"⚠"; label:"Evidence hash mismatch at seq 4211"; col:"colorTrustDenied"; outline:true; italic:false; bold:true; elev:true; block:true }
        ListElement { tag:"◆ Cognitive Core"; label:"· Предлагам да приложа update-а (R2)."; col:"colorActionAi"; outline:true; italic:true; bold:false; elev:false; block:true }
        ListElement { tag:"◉ Requires operator approval"; label:"system.apply_update(channel=stable) · risk R2"; col:"colorActionHuman"; outline:false; italic:false; bold:false; elev:true; block:true }
        ListElement { tag:"AUDIT"; label:"09:41 AI proposed · 09:39 HUMAN approved"; col:"colorActionSystem"; outline:false; italic:true; bold:false; elev:false; block:true }
        ListElement { tag:"⟶"; label:"created → policy → approved → executing → verifying"; col:"colorAccent"; outline:false; italic:false; bold:false; elev:true; block:true }
        ListElement { tag:"▸"; label:"Security & Integrity · 4 surfaces"; col:"colorAccent"; outline:true; italic:false; bold:false; elev:false; block:true }
        ListElement { tag:"▸"; label:"Off-host backup pending · INV-033"; col:"colorWarning"; outline:false; italic:false; bold:false; elev:true; block:true }
    }
    Text { x:24; y:20; text:"AIOS компоненти — KDE (QML) от AiosTokens"; font.pixelSize:24; font.bold:true; color: AiosTokens.colorTextPrimary }
    Column {
        x:24; y:64; width: win.width-48; spacing:10
        Repeater {
            model: comps
            Rectangle {
                radius: 8
                color: model.elev ? AiosTokens.colorSurface : AiosTokens.colorSurfaceVariant
                border.width: model.outline ? 1 : (model.elev ? 1 : 0)
                border.color: model.outline ? AiosTokens[model.col] : AiosTokens.colorBorder
                width: model.block ? (win.width-48) : (row.implicitWidth+24)
                height: row.implicitHeight+16
                Row { id: row; x:12; y:8; spacing:6
                    Text { text: model.tag; color: AiosTokens[model.col]; font.bold:true; font.family:"monospace" }
                    Text { text: model.label; color: AiosTokens[model.col]; font.italic: model.italic; font.bold: model.bold }
                }
            }
        }
    }
}
