use anyhow::Result;
use std::path::Path;

use crate::config::Config;

/// Configuration options for RDP connection
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // Fields will be used when features are implemented
pub struct ConnectionConfig {
    pub clipboard: bool,
    pub map_drives: bool,
    pub password: String,
    pub store_password: bool,
    pub burn_after_reading: bool,
}

/// Show native macOS configuration dialog
///
/// Returns None if user cancelled, Some(config) if user clicked OK
pub fn show_config_dialog(
    rdp_file: &Path,
    cached_password: Option<&str>,
) -> Result<Option<ConnectionConfig>> {
    #[cfg(target_os = "macos")]
    {
        show_macos_dialog(rdp_file, cached_password)
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Fallback for non-macOS: use defaults and prompt for password
        let password = rpassword::prompt_password("Password: ")?;
        Ok(Some(ConnectionConfig {
            password,
            ..Default::default()
        }))
    }
}

// ============================================================================
// macOS Implementation using Cocoa
// ============================================================================

#[cfg(target_os = "macos")]
mod macos {
    #![allow(deprecated)] // cocoa crate is deprecated but still functional

    use super::*;
    use cocoa::appkit::NSApplicationActivationPolicy;
    use cocoa::base::{NO, YES, id, nil};
    use cocoa::foundation::{NSPoint, NSRect, NSSize, NSString};
    use objc::{class, msg_send, sel, sel_impl};

    // Constants for better readability
    const BUTTON_TYPE_SWITCH: i64 = 3; // NSButtonTypeSwitch
    const STATE_OFF: isize = 0; // NSControlStateValueOff
    const STATE_ON: isize = 1; // NSControlStateValueOn
    const ALERT_STYLE_INFO: i64 = 1; // NSAlertStyleInformational
    const ALERT_FIRST_BUTTON: isize = 1000; // NSAlertFirstButtonReturn

    // Dialog dimensions
    const VIEW_WIDTH: f64 = 400.0;
    const VIEW_HEIGHT: f64 = 220.0;
    const MARGIN_LEFT: f64 = 20.0;
    const CONTROL_WIDTH: f64 = 360.0;

    /// Helper: Create an NSString from Rust string
    unsafe fn ns_string(s: &str) -> id {
        unsafe { NSString::alloc(nil).init_str(s) }
    }

    /// Helper: Create a checkbox at given position
    unsafe fn create_checkbox(x: f64, y: f64, width: f64, title: &str, checked: bool) -> id {
        let ns_button = class!(NSButton);
        let checkbox: id = unsafe { msg_send![ns_button, alloc] };
        let frame = NSRect::new(NSPoint::new(x, y), NSSize::new(width, 20.0));
        let checkbox: id = unsafe { msg_send![checkbox, initWithFrame: frame] };

        unsafe {
            let _: () = msg_send![checkbox, setButtonType: BUTTON_TYPE_SWITCH];
            let _: () = msg_send![checkbox, setTitle: ns_string(title)];
            let state = if checked { STATE_ON } else { STATE_OFF };
            let _: () = msg_send![checkbox, setState: state];
        }

        checkbox
    }

    /// Helper: Create a non-editable label at given position
    unsafe fn create_label(x: f64, y: f64, width: f64, height: f64, text: &str) -> id {
        let ns_textfield = class!(NSTextField);
        let label: id = unsafe { msg_send![ns_textfield, alloc] };
        let frame = NSRect::new(NSPoint::new(x, y), NSSize::new(width, height));
        let label: id = unsafe { msg_send![label, initWithFrame: frame] };

        unsafe {
            let _: () = msg_send![label, setStringValue: ns_string(text)];
            let _: () = msg_send![label, setBezeled: NO];
            let _: () = msg_send![label, setDrawsBackground: NO];
            let _: () = msg_send![label, setEditable: NO];
            let _: () = msg_send![label, setSelectable: NO];
        }

        label
    }

    /// Helper: Create a secure password field at given position
    unsafe fn create_password_field(x: f64, y: f64, width: f64, default_value: Option<&str>) -> id {
        // Use NSSecureTextField to mask password (shows bullets)
        // Paste works thanks to the Edit menu created in activate_application()
        let ns_secure = class!(NSSecureTextField);
        let field: id = unsafe { msg_send![ns_secure, alloc] };
        let frame = NSRect::new(NSPoint::new(x, y), NSSize::new(width, 24.0));
        let field: id = unsafe { msg_send![field, initWithFrame: frame] };

        unsafe {
            // Add placeholder text
            let placeholder = ns_string("Enter password or paste (Cmd+V)");
            let _: () = msg_send![field, setPlaceholderString: placeholder];

            if let Some(value) = default_value {
                let _: () = msg_send![field, setStringValue: ns_string(value)];
            }
        }

        field
    }

    /// Helper: Get checkbox state (true if checked)
    unsafe fn get_checkbox_state(checkbox: id) -> bool {
        let state: isize = unsafe { msg_send![checkbox, state] };
        state == STATE_ON
    }

    /// Helper: Get text from a text field
    unsafe fn get_text_field_value(field: id) -> String {
        unsafe {
            let nsstring: id = msg_send![field, stringValue];
            let cstr: *const i8 = msg_send![nsstring, UTF8String];

            if cstr.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(cstr).to_string_lossy().to_string()
            }
        }
    }

    /// Activate the macOS app so it can receive keyboard focus
    unsafe fn activate_application() {
        unsafe {
            let ns_app = class!(NSApplication);
            let app: id = msg_send![ns_app, sharedApplication];

            // Set activation policy to Regular (needed for CLI apps to receive focus)
            let _: () = msg_send![
                app,
                setActivationPolicy: NSApplicationActivationPolicy::NSApplicationActivationPolicyRegular
            ];

            // Create a minimal Edit menu to enable Cmd+V paste
            create_edit_menu(app);

            // Bring app to front
            let _: () = msg_send![app, activateIgnoringOtherApps: YES];
        }
    }

    /// Create a minimal Edit menu to enable standard shortcuts (Cmd+V, etc.)
    unsafe fn create_edit_menu(app: id) {
        unsafe {
            let main_menu: id = msg_send![class!(NSMenu), alloc];
            let main_menu: id = msg_send![main_menu, init];

            // Create Edit menu
            let edit_menu: id = msg_send![class!(NSMenu), alloc];
            let edit_menu: id = msg_send![edit_menu, initWithTitle: ns_string("Edit")];

            // Add Paste item (Cmd+V)
            let paste_title = ns_string("Paste");
            let paste_action = sel!(paste:);
            let paste_key = ns_string("v");
            let _paste_item: id = msg_send![edit_menu, addItemWithTitle:paste_title action:paste_action keyEquivalent:paste_key];

            // Add Copy item (Cmd+C)
            let copy_title = ns_string("Copy");
            let copy_action = sel!(copy:);
            let copy_key = ns_string("c");
            let _copy_item: id = msg_send![edit_menu, addItemWithTitle:copy_title action:copy_action keyEquivalent:copy_key];

            // Add Cut item (Cmd+X)
            let cut_title = ns_string("Cut");
            let cut_action = sel!(cut:);
            let cut_key = ns_string("x");
            let _cut_item: id = msg_send![edit_menu, addItemWithTitle:cut_title action:cut_action keyEquivalent:cut_key];

            // Add Select All item (Cmd+A)
            let select_title = ns_string("Select All");
            let select_action = sel!(selectAll:);
            let select_key = ns_string("a");
            let _select_item: id = msg_send![edit_menu, addItemWithTitle:select_title action:select_action keyEquivalent:select_key];

            // Create Edit menu item and add submenu
            let edit_item: id = msg_send![class!(NSMenuItem), alloc];
            let edit_item: id = msg_send![edit_item, init];
            let _: () = msg_send![edit_item, setSubmenu: edit_menu];

            // Add to main menu
            let _: () = msg_send![main_menu, addItem: edit_item];

            // Set as app menu
            let _: () = msg_send![app, setMainMenu: main_menu];
        }
    }

    /// Create and configure the NSAlert dialog
    unsafe fn create_alert(rdp_name: &str) -> id {
        unsafe {
            let ns_alert = class!(NSAlert);
            let alert: id = msg_send![ns_alert, alloc];
            let alert: id = msg_send![alert, init];

            // Set title and message
            let _: () = msg_send![alert, setMessageText: ns_string("CyberArk RDP - Configuration")];
            let info = format!("Configure connection: {}", rdp_name);
            let _: () = msg_send![alert, setInformativeText: ns_string(&info)];
            let _: () = msg_send![alert, setAlertStyle: ALERT_STYLE_INFO];

            // Add buttons
            let _: id = msg_send![alert, addButtonWithTitle: ns_string("Connect")];
            let _: id = msg_send![alert, addButtonWithTitle: ns_string("Cancel")];

            alert
        }
    }

    /// Create the container view with all controls
    unsafe fn create_controls_view(
        cached_password: Option<&str>,
        preferences: &crate::config::Preferences,
    ) -> (id, id, id, id, id, id) {
        unsafe {
            // Create container view
            let ns_view = class!(NSView);
            let view: id = msg_send![ns_view, alloc];
            let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(VIEW_WIDTH, VIEW_HEIGHT));
            let view: id = msg_send![view, initWithFrame: frame];

            // Create all controls (from top to bottom) with saved preferences
            let clipboard_cb = create_checkbox(
                MARGIN_LEFT,
                190.0,
                CONTROL_WIDTH,
                "Enable clipboard redirection",
                preferences.clipboard,
            );
            let mapdrives_cb = create_checkbox(
                MARGIN_LEFT,
                160.0,
                CONTROL_WIDTH,
                "Map local drives",
                preferences.map_drives,
            );

            let pwd_label = create_label(MARGIN_LEFT, 130.0, 100.0, 20.0, "Password:");
            let pwd_field =
                create_password_field(MARGIN_LEFT, 100.0, CONTROL_WIDTH, cached_password);

            // Show cache hint if password is cached
            if cached_password.is_some() {
                let cache_label =
                    create_label(MARGIN_LEFT, 75.0, CONTROL_WIDTH, 16.0, "(cached password)");
                let _: () = msg_send![view, addSubview: cache_label];
            }

            let store_cb = create_checkbox(
                MARGIN_LEFT,
                45.0,
                CONTROL_WIDTH,
                "Store password in keychain (12h)",
                false, // Always false by default (not saved)
            );
            let burn_cb = create_checkbox(
                MARGIN_LEFT,
                15.0,
                CONTROL_WIDTH,
                "Delete .rdp file after connection",
                preferences.burn_after_reading,
            );

            // Add all controls to view
            let _: () = msg_send![view, addSubview: clipboard_cb];
            let _: () = msg_send![view, addSubview: mapdrives_cb];
            let _: () = msg_send![view, addSubview: pwd_label];
            let _: () = msg_send![view, addSubview: pwd_field];
            let _: () = msg_send![view, addSubview: store_cb];
            let _: () = msg_send![view, addSubview: burn_cb];

            (
                view,
                clipboard_cb,
                mapdrives_cb,
                pwd_field,
                store_cb,
                burn_cb,
            )
        }
    }

    pub(super) fn show_dialog(
        rdp_file: &Path,
        cached_password: Option<&str>,
    ) -> Result<Option<ConnectionConfig>> {
        // Load config to get user preferences
        let config = Config::load().unwrap_or_default();

        unsafe {
            // Step 1: Activate the application
            activate_application();

            // Step 2: Get RDP file name
            let rdp_name = rdp_file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Remote Desktop");

            // Step 3: Create the alert dialog
            let alert = create_alert(rdp_name);

            // Step 4: Create all controls
            let (view, clipboard_cb, mapdrives_cb, pwd_field, store_cb, burn_cb) =
                create_controls_view(cached_password, &config.preferences);

            // Step 5: Add controls to alert
            let _: () = msg_send![alert, setAccessoryView: view];

            // Step 6: Configure window and focus
            let window: id = msg_send![alert, window];

            // Force window to appear in front and switch to its workspace
            let _: () = msg_send![window, makeKeyAndOrderFront: nil];
            let _: () = msg_send![window, orderFrontRegardless];

            // Set focus to password field
            let _: () = msg_send![window, setInitialFirstResponder: pwd_field];

            // Step 7: Show dialog and wait for user response
            let response: isize = msg_send![alert, runModal];

            // Step 8: Check if user clicked "Connect" or "Cancel"
            if response != ALERT_FIRST_BUTTON {
                return Ok(None); // User cancelled
            }

            // Step 9: Get values from controls
            let password = get_text_field_value(pwd_field);

            if password.is_empty() {
                return Ok(None); // Empty password = cancel
            }

            Ok(Some(ConnectionConfig {
                clipboard: get_checkbox_state(clipboard_cb),
                map_drives: get_checkbox_state(mapdrives_cb),
                password,
                store_password: get_checkbox_state(store_cb),
                burn_after_reading: get_checkbox_state(burn_cb),
            }))
        }
    }
}

#[cfg(target_os = "macos")]
fn show_macos_dialog(
    rdp_file: &Path,
    cached_password: Option<&str>,
) -> Result<Option<ConnectionConfig>> {
    macos::show_dialog(rdp_file, cached_password)
}
