use std::path::PathBuf;

use tracing::{debug, info};

use crate::container::WaydroidContainer;
use crate::error::WaydroidError;
use crate::AndroidAppState;

pub fn install_apk(
    container: &mut WaydroidContainer,
    apk_path: &PathBuf,
    package_name: impl Into<String>,
) -> Result<(), WaydroidError> {
    let pkg = package_name.into();

    if container.container_state != crate::WaydroidContainerState::Running {
        return Err(WaydroidError::container_init_failed(
            container.capsule_id_str(),
            format!(
                "container must be Running to install APK, current state: {:?}",
                container.container_state
            ),
        ));
    }

    if let Some((_, existing_state)) = container
        .app_list
        .iter()
        .find(|(name, _)| name == &pkg)
    {
        if *existing_state == AndroidAppState::Installed
            || *existing_state == AndroidAppState::Running
            || *existing_state == AndroidAppState::Suspended
        {
            return Err(WaydroidError::apk_install_failed(
                &pkg,
                format!(
                    "package already present with state: {:?}",
                    existing_state
                ),
            ));
        }
    }

    debug!(package = %pkg, path = %apk_path.display(), "installing APK");

    container
        .app_list
        .push((pkg.clone(), AndroidAppState::Installing));

    let app_name = resolve_human_name(&pkg);

    info!(package = %pkg, name = %app_name, "APK installed");

    container
        .app_list
        .retain(|(name, _)| name != &pkg);
    container
        .app_list
        .push((pkg, AndroidAppState::Installed));

    Ok(())
}

pub fn uninstall_app(
    container: &mut WaydroidContainer,
    package_name: impl Into<String>,
) -> Result<(), WaydroidError> {
    let pkg: String = package_name.into();

    let found = container
        .app_list
        .iter()
        .any(|(name, _)| name == &pkg);

    if !found {
        return Err(WaydroidError::app_not_found(&pkg));
    }

    debug!(package = %pkg, "uninstalling Android app");

    container.app_list.retain(|(name, _)| name != &pkg);
    container
        .app_list
        .push((pkg, AndroidAppState::Uninstalled));

    info!("app uninstalled");

    Ok(())
}

pub fn launch_app(
    container: &mut WaydroidContainer,
    package_name: impl Into<String>,
) -> Result<(), WaydroidError> {
    let pkg: String = package_name.into();

    if container.container_state != crate::WaydroidContainerState::Running {
        return Err(WaydroidError::container_init_failed(
            container.capsule_id_str(),
            format!(
                "container must be Running to launch app, current state: {:?}",
                container.container_state
            ),
        ));
    }

    let found = container
        .app_list
        .iter()
        .any(|(name, state)| name == &pkg && *state == AndroidAppState::Installed);

    if !found {
        return Err(WaydroidError::app_not_found(&pkg));
    }

    debug!(package = %pkg, "launching Android app");

    container.app_list.retain(|(name, _)| name != &pkg);
    container.app_list.push((pkg, AndroidAppState::Running));

    info!("app launched");

    Ok(())
}

pub fn suspend_app(
    container: &mut WaydroidContainer,
    package_name: impl Into<String>,
) -> Result<(), WaydroidError> {
    let pkg: String = package_name.into();

    let found = container
        .app_list
        .iter()
        .any(|(name, state)| name == &pkg && *state == AndroidAppState::Running);

    if !found {
        return Err(WaydroidError::app_not_found(&pkg));
    }

    debug!(package = %pkg, "suspending Android app");

    container.app_list.retain(|(name, _)| name != &pkg);
    container.app_list.push((pkg, AndroidAppState::Suspended));

    info!("app suspended");

    Ok(())
}

pub fn list_apps(container: &WaydroidContainer) -> Vec<(String, AndroidAppState)> {
    container.app_list.clone()
}

#[must_use]
pub fn resolve_human_name(package_name: &str) -> String {
    if package_name.contains('.') {
        let parts: Vec<&str> = package_name.split('.').collect();
        if let Some(last) = parts.last() {
            let mut name = last.replace('_', " ");
            if let (Some(first), Some(rest)) = (name.get(..1), name.get(1..)) {
                name = format!("{}{}", first.to_uppercase(), rest);
            }
            return name;
        }
    }
    String::from("Unknown App")
}

#[must_use]
pub fn generate_desktop_entry(
    package_name: impl Into<String>,
    app_human_name: impl Into<String>,
) -> String {
    let pkg = package_name.into();
    let name = app_human_name.into();

    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={name}\n\
         Comment=Android app running under Waydroid\n\
         Exec=waydroid app launch {pkg}\n\
         Icon=waydroid\n\
         Categories=Android;AIOS;\n\
         X-Waydroid-Package={pkg}\n\
         Terminal=false\n\
         StartupNotify=true\n"
    )
}

pub fn get_app_state(
    container: &WaydroidContainer,
    package_name: &str,
) -> Option<AndroidAppState> {
    container
        .app_list
        .iter()
        .find(|(name, _)| name == package_name)
        .map(|(_, state)| *state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WaydroidContainerState;

    fn make_running_container() -> WaydroidContainer {
        let capsule_id = ulid::Ulid::new();
        let data_path = PathBuf::from(format!("/var/lib/aios/waydroid/{capsule_id}/"));
        let mut container = WaydroidContainer::new(capsule_id)
            .expect("new container");
        container.data_path = data_path;
        container
    }

    #[test]
    fn install_apk_records_app_in_list() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Running;

        let apk_path = PathBuf::from("/tmp/test.apk");
        let result = install_apk(&mut container, &apk_path, "com.example.app");
        assert!(result.is_ok());

        let found = container
            .app_list
            .iter()
            .any(|(name, state)| name == "com.example.app" && *state == AndroidAppState::Installed);
        assert!(found);
    }

    #[test]
    fn install_apk_fails_if_not_running() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Stopped;

        let apk_path = PathBuf::from("/tmp/test.apk");
        let result = install_apk(&mut container, &apk_path, "com.example.app");
        assert!(result.is_err());
    }

    #[test]
    fn uninstall_app_removes_from_list() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Running;
        container
            .app_list
            .push((String::from("com.example.app"), AndroidAppState::Installed));

        let result = uninstall_app(&mut container, "com.example.app");
        assert!(result.is_ok());

        let installed = container
            .app_list
            .iter()
            .any(|(name, state)| name == "com.example.app" && *state == AndroidAppState::Installed);
        assert!(!installed);
    }

    #[test]
    fn uninstall_app_fails_if_not_found() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Running;

        let result = uninstall_app(&mut container, "com.nonexistent.app");
        assert!(result.is_err());
    }

    #[test]
    fn app_lifecycle_running_to_suspended() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Running;
        container
            .app_list
            .push((String::from("com.example.app"), AndroidAppState::Running));

        let result = suspend_app(&mut container, "com.example.app");
        assert!(result.is_ok());

        let suspended = container
            .app_list
            .iter()
            .any(|(name, state)| name == "com.example.app" && *state == AndroidAppState::Suspended);
        assert!(suspended);
    }

    #[test]
    fn desktop_entry_generation_for_package() {
        let entry = generate_desktop_entry("com.example.hello", "Hello World");
        assert!(entry.contains("Name=Hello World"));
        assert!(entry.contains("Exec=waydroid app launch com.example.hello"));
        assert!(entry.contains("X-Waydroid-Package=com.example.hello"));
        assert!(entry.contains("Type=Application"));
        assert!(entry.starts_with("[Desktop Entry]"));
    }

    #[test]
    fn resolve_human_name_handles_standard_package() {
        let name = resolve_human_name("com.example.calculator");
        assert_eq!(name, "Calculator");
    }

    #[test]
    fn resolve_human_name_defaults_to_unknown() {
        let name = resolve_human_name("unknownpkg");
        assert_eq!(name, "Unknown App");
    }

    #[test]
    fn list_apps_returns_cloned_list() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Running;
        container
            .app_list
            .push((String::from("com.a"), AndroidAppState::Installed));
        container
            .app_list
            .push((String::from("com.b"), AndroidAppState::Running));

        let apps = list_apps(&container);
        assert_eq!(apps.len(), 2);
        assert!(apps.contains(&(String::from("com.a"), AndroidAppState::Installed)));
        assert!(apps.contains(&(String::from("com.b"), AndroidAppState::Running)));
    }

    #[test]
    fn get_app_state_returns_correct_state() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Running;
        container
            .app_list
            .push((String::from("com.example.app"), AndroidAppState::Installed));

        let state = get_app_state(&container, "com.example.app");
        assert_eq!(state, Some(AndroidAppState::Installed));

        let none = get_app_state(&container, "com.nonexistent.app");
        assert_eq!(none, None);
    }

    #[test]
    fn install_apk_fails_if_already_installed() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Running;
        container
            .app_list
            .push((String::from("com.example.app"), AndroidAppState::Installed));

        let apk_path = PathBuf::from("/tmp/test.apk");
        let result = install_apk(&mut container, &apk_path, "com.example.app");
        assert!(result.is_err());
    }

    #[test]
    fn launch_app_fails_if_not_running() {
        let mut container = make_running_container();
        container.container_state = WaydroidContainerState::Stopped;

        let result = launch_app(&mut container, "com.example.app");
        assert!(result.is_err());
    }
}
