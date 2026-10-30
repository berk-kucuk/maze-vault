"""English and Turkish strings.

English is the default whatever the system locale. Turkish is one click away
in the title bar (remembered in settings.json) or `maze-vault --lang=tr`.
`t()` falls back to English, then to the key.
"""
from __future__ import annotations

STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "bug_body": "This was a bug, not something you did. Nothing was deleted; the details are in the system journal.",
        "tip_minimize": "Minimize", "tip_maximize": "Maximize / Restore", "tip_close": "Close",
        "tip_settings": "Settings", "tip_language": "Language", "tip_lock": "Lock (Ctrl+L)",
        "tip_sync": "Sync now (F5)", "tip_generator": "Password generator (Ctrl+G)",
        # welcome
        "eyebrow": "PASSWORD MANAGER",
        "hero_title": "Every password,\nsealed in one place.",
        "hero_sub": "Maze Vault is a Bitwarden-compatible client. Your vault is encrypted on this "
                    "computer before it goes anywhere — the server only ever sees ciphertext.",
        "welcome_q": "Where do you want to keep your vault?",
        "opt_server": "My own server",
        "opt_server_sub": "Vaultwarden or any Bitwarden-compatible server. Syncs with the "
                          "Bitwarden app on your phone and the browser extension.",
        "opt_local": "Only this computer",
        "opt_local_sub": "No server, no account. The vault stays here, encrypted. It can be "
                         "moved to a server later.",
        "back": "Back",
        # login
        "login_title": "Sign in to your server",
        "f_server": "SERVER", "f_url": "SERVER ADDRESS", "f_email": "E-MAIL",
        "f_master": "MASTER PASSWORD", "f_confirm": "CONFIRM MASTER PASSWORD", "f_name": "NAME",
        "srv_custom": "Self-hosted (Vaultwarden, Bitwarden)",
        "srv_us": "Bitwarden Cloud (bitwarden.com)", "srv_eu": "Bitwarden Cloud (bitwarden.eu)",
        "ph_url": "https://vault.example.com",
        "btn_login": "Sign in", "logging_in": "Deriving your key and signing in…",
        "tf_title": "Two-step login",
        "tf_body": "Enter the code from your authenticator app or e-mail.",
        "tf_provider": "METHOD", "tf_code": "CODE",
        "tf_authenticator": "Authenticator app", "tf_email": "E-mail code", "tf_yubikey": "YubiKey OTP",
        "tf_send_email": "Send code", "tf_sent": "Code sent to your e-mail.",
        "tf_remember": "Remember this computer", "tf_unsupported":
            "This account only offers two-step methods Maze Vault cannot use yet "
            "(Duo, WebAuthn). Add an authenticator app or e-mail in the web vault.",
        "nd_title": "New device verification",
        "nd_body": "The server sent a verification code to your e-mail. Enter it to confirm this computer.",
        "btn_verify": "Verify",
        # local create
        "local_title": "Create a vault on this computer",
        "local_warn": "Nobody can recover a forgotten master password — not Maze Linux, not "
                      "anyone. Choose one you will remember, or write it down somewhere safe.",
        "ph_local_name": "e.g. Personal",
        "btn_create": "Create vault", "creating": "Creating your vault…",
        "pw_mismatch": "The passwords do not match.",
        "strength_0": "Too short — at least {n} characters", "strength_1": "Weak",
        "strength_2": "Fair", "strength_3": "Good", "strength_4": "Strong",
        "show_pw": "Show", "hide_pw": "Hide",
        # lock
        "lock_title": "Vault locked",
        "btn_unlock": "Unlock", "unlocking": "Unlocking…",
        "use_pin": "Unlock with PIN", "use_master": "Use master password",
        "pin_tries": "{n} tries left", "pin_wiped": "Too many wrong PINs — the PIN was removed. "
                                                    "Unlock with your master password.",
        "add_account": "Add another vault", "switch_account": "Switch vault",
        "local_vault": "Local vault · this computer",
        # vault
        "nav_all": "All items", "nav_fav": "Favorites", "nav_login": "Logins", "nav_card": "Cards",
        "nav_identity": "Identities", "nav_note": "Secure notes", "nav_ssh": "SSH keys",
        "nav_folders": "FOLDERS", "nav_nofolder": "No folder", "nav_trash": "Trash",
        "nav_types": "TYPES", "nav_vault": "VAULT",
        "ph_search": "Search the vault  (Ctrl+F)",
        "btn_new": "New", "new_login": "Login", "new_card": "Card", "new_identity": "Identity",
        "new_note": "Secure note", "new_folder": "New folder…",
        "empty_list": "Nothing here yet.", "empty_search": "No matches.",
        "empty_detail": "Select an item to see it here.",
        "synced_at": "Synced {when}", "synced_never": "Not synced yet", "syncing": "Syncing…",
        "offline": "Offline — showing the last synced copy",
        "just_now": "just now", "min_ago": "{n} min ago", "h_ago": "{n} h ago",
        # detail
        "d_username": "Username", "d_password": "Password", "d_totp": "Verification code (TOTP)",
        "d_uri": "Website", "d_notes": "Notes", "d_fields": "Custom fields",
        "d_history": "Password history", "d_updated": "Updated {date}", "d_created": "Created {date}",
        "d_cardholder": "Cardholder", "d_number": "Number", "d_brand": "Brand",
        "d_expiry": "Expires", "d_code": "Security code",
        "d_name": "Name", "d_email": "E-mail", "d_phone": "Phone", "d_address": "Address",
        "d_company": "Company", "d_ssn": "National ID", "d_passport": "Passport",
        "d_license": "License", "d_public": "Public key", "d_private": "Private key",
        "d_fingerprint": "Fingerprint",
        "d_exp_month": "Expiry month", "d_exp_year": "Expiry year", "d_title": "Title",
        "d_first": "First name", "d_middle": "Middle name", "d_last": "Last name",
        "d_addr1": "Address line 1", "d_addr2": "Address line 2", "d_addr3": "Address line 3",
        "d_city": "City", "d_state": "State / province", "d_postal": "Postal code", "d_country": "Country",
        "btn_edit": "Edit", "btn_copy": "Copy", "btn_copied": "Copied", "btn_open": "Open",
        "btn_restore": "Restore", "btn_purge": "Delete forever…", "btn_delete": "Move to trash",
        "fav_add": "Add to favorites", "fav_remove": "Remove from favorites",
        "damaged": "Part of this item could not be decrypted, so it is read-only here. "
                   "Nothing was changed. Open it in another Bitwarden app to check it.",
        "readonly_org": "You can view this shared item but not change it.",
        "conflict": "This copy was saved because the item was changed on another device at the "
                    "same time. Both versions are kept — compare them and delete the one you "
                    "do not need.",
        "copied_clear": "Copied. The clipboard is cleared in {n} s.",
        "copied": "Copied.",
        # editor
        "ed_new": "New {type}", "ed_edit": "Edit item",
        "ed_folder": "FOLDER", "ed_favorite": "Favorite",
        "ed_uris": "WEBSITES", "ed_add_uri": "Add website", "ed_fields": "CUSTOM FIELDS",
        "ed_add_field": "Add field", "ed_field_name": "Name", "ed_field_value": "Value",
        "ed_hidden": "Hidden", "ed_generate": "Generate", "btn_save": "Save", "btn_cancel": "Cancel",
        "saving": "Encrypting and saving…",
        "ed_name_required": "Give the item a name.",
        "ed_totp_bad": "That is not a valid authenticator key.",
        "ed_conflict_saved": "Someone changed this item on another device meanwhile. Your "
                             "version was saved as a copy — both are in the vault.",
        # trash
        "trash_title": "Move “{name}” to the trash?",
        "trash_body": "Items in the trash can be restored from every Bitwarden app until you "
                      "delete them for good.",
        "purge_title": "Delete “{name}” forever?",
        "purge_body": "This removes the item from the vault on every device. It cannot be undone.",
        "purge_btn": "Delete forever",
        # generator
        "gen_title": "Password generator", "gen_length": "LENGTH", "gen_upper": "A–Z",
        "gen_lower": "a–z", "gen_digits": "0–9", "gen_symbols": "!@#$",
        "gen_ambiguous": "Avoid look-alike characters (I l 1 O 0)",
        "gen_again": "New password", "gen_use": "Use", "gen_bits": "{n} bits of entropy",
        # folders
        "fd_new": "New folder", "fd_rename": "Rename folder", "fd_delete": "Delete folder",
        "fd_delete_body": "The folder is deleted; its items move to “No folder”. No item is deleted.",
        # settings
        "st_title": "Settings", "st_language": "LANGUAGE", "st_security": "SECURITY",
        "st_autolock": "Lock after inactivity", "st_never": "Never",
        "st_minutes": "{n} minutes", "st_minute": "1 minute", "st_hour": "1 hour", "st_hours": "{n} hours",
        "st_screenlock": "Lock when the screen locks", "st_sleep": "Lock before sleep",
        "st_clipboard": "Clear copied secrets after", "st_seconds": "{n} seconds",
        "st_pin": "PIN", "st_pin_sub": "Unlock with a short PIN while Maze Vault is running. "
                                       "After a restart the master password is needed again.",
        "st_pin_set": "Set PIN…", "st_pin_change": "Change PIN…", "st_pin_remove": "Remove PIN",
        "st_account": "ACCOUNT", "st_server": "Server: {url}", "st_local": "Local vault: {path}",
        "st_signout": "Sign out on this computer…",
        "st_signout_title": "Sign out of {email}?",
        "st_signout_body": "This computer forgets the account. Its encrypted copy is kept in an "
                           "archive folder in case the server ever loses data. Nothing changes "
                           "on the server; sign in again any time.",
        "st_about": "Maze Vault {ver}",
        # PIN
        "pin_title": "Set a PIN", "pin_body": "4 to 12 digits. After 5 wrong tries the PIN is "
                                              "removed and the master password is needed.",
        "pin_new": "PIN", "pin_again": "PIN AGAIN", "pin_mismatch": "The PINs do not match.",
        "pin_set_ok": "PIN set.", "pin_removed": "PIN removed.", "pin_wrong": "Wrong PIN.",
        # quit
        "locked_msg": "Vault locked.", "synced_msg": "Vault synced.",
        # errors
        "e_wrong_password": "Wrong master password.",
        "e_wrong_pin": "Wrong PIN.",
        "e_pin_wiped": "Too many wrong PINs — the PIN was removed.",
        "e_bad_pin": "A PIN is 4 to 12 digits.",
        "e_network": "Cannot reach the server. Check the address and your connection.",
        "e_tls": "The server's certificate is not trusted ({detail}).",
        "e_insecure_url": "Only https:// addresses are allowed (http only for this computer).",
        "e_bad_url": "That is not a valid server address.",
        "e_kdf_unsafe": "The server asked for unsafe key settings ({detail}). Refused — raise the "
                        "KDF iterations in the web vault.",
        "e_kdf_downgrade": "The server now asks for weaker key settings than before. This can "
                           "mean the server was tampered with, so Maze Vault refused to sign in.",
        "e_kdf_unsupported": "This account uses a key setting Maze Vault does not know.",
        "e_captcha": "The server wants a CAPTCHA. Sign in once with the official app or use an API key.",
        "e_rate_limited": "Too many attempts. Wait a minute and try again.",
        "e_server": "The server had an error ({detail}).",
        "e_relogin": "Your session expired. Sign in again with your master password.",
        "e_unauthorized": "The server refused access. Sign in again.",
        "e_two_factor": "Two-step login required.",
        "e_verify_email": "The server requires e-mail verification first.",
        "e_not_found": "Not found on the server.",
        "e_rejected": "The server refused the request ({detail}).",
        "e_bad_response": "The server sent an unexpected answer.",
        "e_mac_mismatch": "Data failed its integrity check and was not used.",
        "e_item_damaged": "This item could not be fully decrypted and cannot be edited.",
        "e_locked": "The vault is locked.",
        "e_no_key": "No key for this item.",
        "e_not_in_trash": "Only items in the trash can be deleted for good.",
        "e_failed": "Something went wrong.",
    },
    "tr": {
        "bug_body": "Bu bir hataydı, senin yaptığın bir şey değil. Hiçbir şey silinmedi; ayrıntılar sistem günlüğünde.",
        "tip_minimize": "Küçült", "tip_maximize": "Büyüt / Geri al", "tip_close": "Kapat",
        "tip_settings": "Ayarlar", "tip_language": "Dil", "tip_lock": "Kilitle (Ctrl+L)",
        "tip_sync": "Şimdi senkronize et (F5)", "tip_generator": "Şifre üretici (Ctrl+G)",
        "eyebrow": "ŞİFRE YÖNETİCİSİ",
        "hero_title": "Tüm şifrelerin,\ntek bir yerde mühürlü.",
        "hero_sub": "Maze Vault, Bitwarden uyumlu bir istemcidir. Kasan bir yere gitmeden önce bu "
                    "bilgisayarda şifrelenir — sunucu yalnızca şifreli veriyi görür.",
        "welcome_q": "Kasanı nerede tutmak istiyorsun?",
        "opt_server": "Kendi sunucum",
        "opt_server_sub": "Vaultwarden veya Bitwarden uyumlu herhangi bir sunucu. Telefondaki "
                          "Bitwarden uygulaması ve tarayıcı eklentisiyle senkronize olur.",
        "opt_local": "Sadece bu bilgisayarda",
        "opt_local_sub": "Sunucu yok, hesap yok. Kasa burada, şifreli olarak kalır. Daha sonra "
                         "bir sunucuya taşınabilir.",
        "back": "Geri",
        "login_title": "Sunucuna giriş yap",
        "f_server": "SUNUCU", "f_url": "SUNUCU ADRESİ", "f_email": "E-POSTA",
        "f_master": "ANA PAROLA", "f_confirm": "ANA PAROLA TEKRAR", "f_name": "İSİM",
        "srv_custom": "Kendi sunucum (Vaultwarden, Bitwarden)",
        "srv_us": "Bitwarden Cloud (bitwarden.com)", "srv_eu": "Bitwarden Cloud (bitwarden.eu)",
        "ph_url": "https://vault.ornek.com",
        "btn_login": "Giriş yap", "logging_in": "Anahtar türetiliyor ve giriş yapılıyor…",
        "tf_title": "İki adımlı giriş",
        "tf_body": "Kimlik doğrulayıcı uygulamandaki veya e-postandaki kodu gir.",
        "tf_provider": "YÖNTEM", "tf_code": "KOD",
        "tf_authenticator": "Kimlik doğrulayıcı uygulama", "tf_email": "E-posta kodu",
        "tf_yubikey": "YubiKey OTP",
        "tf_send_email": "Kod gönder", "tf_sent": "Kod e-postana gönderildi.",
        "tf_remember": "Bu bilgisayarı hatırla", "tf_unsupported":
            "Bu hesap yalnızca Maze Vault'un henüz kullanamadığı iki adımlı yöntemler sunuyor "
            "(Duo, WebAuthn). Web kasasından bir kimlik doğrulayıcı uygulama veya e-posta ekle.",
        "nd_title": "Yeni cihaz doğrulaması",
        "nd_body": "Sunucu e-postana bir doğrulama kodu gönderdi. Bu bilgisayarı onaylamak için gir.",
        "btn_verify": "Doğrula",
        "local_title": "Bu bilgisayarda bir kasa oluştur",
        "local_warn": "Unutulan bir ana parolayı kimse kurtaramaz — ne Maze Linux ne başkası. "
                      "Hatırlayacağın bir parola seç ya da güvenli bir yere yaz.",
        "ph_local_name": "örn. Kişisel",
        "btn_create": "Kasayı oluştur", "creating": "Kasan oluşturuluyor…",
        "pw_mismatch": "Parolalar aynı değil.",
        "strength_0": "Çok kısa — en az {n} karakter", "strength_1": "Zayıf",
        "strength_2": "Orta", "strength_3": "İyi", "strength_4": "Güçlü",
        "show_pw": "Göster", "hide_pw": "Gizle",
        "lock_title": "Kasa kilitli",
        "btn_unlock": "Kilidi aç", "unlocking": "Kilit açılıyor…",
        "use_pin": "PIN ile aç", "use_master": "Ana parolayı kullan",
        "pin_tries": "{n} deneme hakkı kaldı", "pin_wiped": "Çok fazla yanlış PIN — PIN kaldırıldı. "
                                                            "Ana parolanla aç.",
        "add_account": "Başka bir kasa ekle", "switch_account": "Kasa değiştir",
        "local_vault": "Yerel kasa · bu bilgisayar",
        "nav_all": "Tüm kayıtlar", "nav_fav": "Favoriler", "nav_login": "Girişler", "nav_card": "Kartlar",
        "nav_identity": "Kimlikler", "nav_note": "Güvenli notlar", "nav_ssh": "SSH anahtarları",
        "nav_folders": "KLASÖRLER", "nav_nofolder": "Klasörsüz", "nav_trash": "Çöp kutusu",
        "nav_types": "TÜRLER", "nav_vault": "KASA",
        "ph_search": "Kasada ara  (Ctrl+F)",
        "btn_new": "Yeni", "new_login": "Giriş", "new_card": "Kart", "new_identity": "Kimlik",
        "new_note": "Güvenli not", "new_folder": "Yeni klasör…",
        "empty_list": "Burada henüz bir şey yok.", "empty_search": "Eşleşme yok.",
        "empty_detail": "Görmek için bir kayıt seç.",
        "synced_at": "Senkronize: {when}", "synced_never": "Henüz senkronize edilmedi",
        "syncing": "Senkronize ediliyor…",
        "offline": "Çevrimdışı — son senkronize edilen kopya gösteriliyor",
        "just_now": "az önce", "min_ago": "{n} dk önce", "h_ago": "{n} sa önce",
        "d_username": "Kullanıcı adı", "d_password": "Şifre", "d_totp": "Doğrulama kodu (TOTP)",
        "d_uri": "Web sitesi", "d_notes": "Notlar", "d_fields": "Özel alanlar",
        "d_history": "Şifre geçmişi", "d_updated": "Güncellendi: {date}", "d_created": "Oluşturuldu: {date}",
        "d_cardholder": "Kart sahibi", "d_number": "Numara", "d_brand": "Marka",
        "d_expiry": "Son kullanma", "d_code": "Güvenlik kodu",
        "d_name": "Ad", "d_email": "E-posta", "d_phone": "Telefon", "d_address": "Adres",
        "d_company": "Şirket", "d_ssn": "Kimlik no", "d_passport": "Pasaport",
        "d_license": "Ehliyet", "d_public": "Açık anahtar", "d_private": "Özel anahtar",
        "d_fingerprint": "Parmak izi",
        "d_exp_month": "Son kullanma ayı", "d_exp_year": "Son kullanma yılı", "d_title": "Unvan",
        "d_first": "Ad", "d_middle": "İkinci ad", "d_last": "Soyad",
        "d_addr1": "Adres satırı 1", "d_addr2": "Adres satırı 2", "d_addr3": "Adres satırı 3",
        "d_city": "Şehir", "d_state": "İl / eyalet", "d_postal": "Posta kodu", "d_country": "Ülke",
        "btn_edit": "Düzenle", "btn_copy": "Kopyala", "btn_copied": "Kopyalandı", "btn_open": "Aç",
        "btn_restore": "Geri yükle", "btn_purge": "Kalıcı olarak sil…", "btn_delete": "Çöp kutusuna taşı",
        "fav_add": "Favorilere ekle", "fav_remove": "Favorilerden çıkar",
        "damaged": "Bu kaydın bir kısmı çözülemedi, bu yüzden burada salt okunur. Hiçbir şey "
                   "değiştirilmedi. Kontrol etmek için başka bir Bitwarden uygulamasında aç.",
        "readonly_org": "Bu paylaşılan kaydı görebilirsin ama değiştiremezsin.",
        "conflict": "Bu kopya, kayıt aynı anda başka bir cihazda değiştirildiği için kaydedildi. "
                    "İki sürüm de korunuyor — karşılaştır ve gerekmeyeni sil.",
        "copied_clear": "Kopyalandı. Pano {n} sn sonra temizlenecek.",
        "copied": "Kopyalandı.",
        "ed_new": "Yeni {type}", "ed_edit": "Kaydı düzenle",
        "ed_folder": "KLASÖR", "ed_favorite": "Favori",
        "ed_uris": "WEB SİTELERİ", "ed_add_uri": "Web sitesi ekle", "ed_fields": "ÖZEL ALANLAR",
        "ed_add_field": "Alan ekle", "ed_field_name": "Ad", "ed_field_value": "Değer",
        "ed_hidden": "Gizli", "ed_generate": "Üret", "btn_save": "Kaydet", "btn_cancel": "Vazgeç",
        "saving": "Şifreleniyor ve kaydediliyor…",
        "ed_name_required": "Kayda bir ad ver.",
        "ed_totp_bad": "Bu geçerli bir doğrulayıcı anahtarı değil.",
        "ed_conflict_saved": "Bu kayıt bu sırada başka bir cihazda değiştirildi. Senin sürümün "
                             "bir kopya olarak kaydedildi — ikisi de kasada.",
        "trash_title": "“{name}” çöp kutusuna taşınsın mı?",
        "trash_body": "Çöp kutusundaki kayıtlar, sen kalıcı olarak silene kadar her Bitwarden "
                      "uygulamasından geri yüklenebilir.",
        "purge_title": "“{name}” kalıcı olarak silinsin mi?",
        "purge_body": "Bu, kaydı her cihazdaki kasadan kaldırır. Geri alınamaz.",
        "purge_btn": "Kalıcı olarak sil",
        "gen_title": "Şifre üretici", "gen_length": "UZUNLUK", "gen_upper": "A–Z",
        "gen_lower": "a–z", "gen_digits": "0–9", "gen_symbols": "!@#$",
        "gen_ambiguous": "Birbirine benzeyen karakterleri kullanma (I l 1 O 0)",
        "gen_again": "Yeni şifre", "gen_use": "Kullan", "gen_bits": "{n} bit entropi",
        "fd_new": "Yeni klasör", "fd_rename": "Klasörü yeniden adlandır", "fd_delete": "Klasörü sil",
        "fd_delete_body": "Klasör silinir; içindeki kayıtlar “Klasörsüz”e taşınır. Hiçbir kayıt silinmez.",
        "st_title": "Ayarlar", "st_language": "DİL", "st_security": "GÜVENLİK",
        "st_autolock": "Kullanılmazsa kilitle", "st_never": "Asla",
        "st_minutes": "{n} dakika", "st_minute": "1 dakika", "st_hour": "1 saat", "st_hours": "{n} saat",
        "st_screenlock": "Ekran kilitlenince kilitle", "st_sleep": "Uykudan önce kilitle",
        "st_clipboard": "Kopyalanan gizli bilgileri şu süre sonra temizle", "st_seconds": "{n} saniye",
        "st_pin": "PIN", "st_pin_sub": "Maze Vault çalıştığı sürece kısa bir PIN ile aç. "
                                       "Yeniden başlatınca ana parola tekrar gerekir.",
        "st_pin_set": "PIN belirle…", "st_pin_change": "PIN'i değiştir…", "st_pin_remove": "PIN'i kaldır",
        "st_account": "HESAP", "st_server": "Sunucu: {url}", "st_local": "Yerel kasa: {path}",
        "st_signout": "Bu bilgisayarda oturumu kapat…",
        "st_signout_title": "{email} oturumu kapatılsın mı?",
        "st_signout_body": "Bu bilgisayar hesabı unutur. Sunucu bir gün veri kaybederse diye "
                           "şifreli kopyası bir arşiv klasöründe saklanır. Sunucuda hiçbir şey "
                           "değişmez; istediğin zaman tekrar giriş yapabilirsin.",
        "st_about": "Maze Vault {ver}",
        "pin_title": "PIN belirle", "pin_body": "4 ila 12 rakam. 5 yanlış denemeden sonra PIN "
                                                "kaldırılır ve ana parola gerekir.",
        "pin_new": "PIN", "pin_again": "PIN TEKRAR", "pin_mismatch": "PIN'ler aynı değil.",
        "pin_set_ok": "PIN belirlendi.", "pin_removed": "PIN kaldırıldı.", "pin_wrong": "Yanlış PIN.",
        "locked_msg": "Kasa kilitlendi.", "synced_msg": "Kasa senkronize edildi.",
        "e_wrong_password": "Ana parola yanlış.",
        "e_wrong_pin": "PIN yanlış.",
        "e_pin_wiped": "Çok fazla yanlış PIN — PIN kaldırıldı.",
        "e_bad_pin": "PIN 4 ila 12 rakamdan oluşur.",
        "e_network": "Sunucuya ulaşılamıyor. Adresi ve bağlantını kontrol et.",
        "e_tls": "Sunucunun sertifikasına güvenilmiyor ({detail}).",
        "e_insecure_url": "Yalnızca https:// adreslerine izin var (http yalnızca bu bilgisayar için).",
        "e_bad_url": "Bu geçerli bir sunucu adresi değil.",
        "e_kdf_unsafe": "Sunucu güvensiz anahtar ayarları istedi ({detail}). Reddedildi — web "
                        "kasasından KDF tur sayısını artır.",
        "e_kdf_downgrade": "Sunucu artık öncekinden daha zayıf anahtar ayarları istiyor. Bu, "
                           "sunucuya müdahale edildiği anlamına gelebilir; Maze Vault girişi reddetti.",
        "e_kdf_unsupported": "Bu hesap Maze Vault'un tanımadığı bir anahtar ayarı kullanıyor.",
        "e_captcha": "Sunucu CAPTCHA istiyor. Bir kez resmi uygulamayla giriş yap veya API anahtarı kullan.",
        "e_rate_limited": "Çok fazla deneme. Bir dakika bekleyip tekrar dene.",
        "e_server": "Sunucuda bir hata oluştu ({detail}).",
        "e_relogin": "Oturumun süresi doldu. Ana parolanla tekrar giriş yap.",
        "e_unauthorized": "Sunucu erişimi reddetti. Tekrar giriş yap.",
        "e_two_factor": "İki adımlı giriş gerekiyor.",
        "e_verify_email": "Sunucu önce e-posta doğrulaması istiyor.",
        "e_not_found": "Sunucuda bulunamadı.",
        "e_rejected": "Sunucu isteği reddetti ({detail}).",
        "e_bad_response": "Sunucu beklenmeyen bir yanıt gönderdi.",
        "e_mac_mismatch": "Veri bütünlük kontrolünden geçemedi ve kullanılmadı.",
        "e_item_damaged": "Bu kayıt tamamen çözülemedi ve düzenlenemez.",
        "e_locked": "Kasa kilitli.",
        "e_no_key": "Bu kayıt için anahtar yok.",
        "e_not_in_trash": "Yalnızca çöp kutusundaki kayıtlar kalıcı olarak silinebilir.",
        "e_failed": "Bir şeyler ters gitti.",
    },
}

_lang = "en"


def set_language(lang: str) -> None:
    global _lang
    _lang = lang if lang in STRINGS else "en"


def language() -> str:
    return _lang


def t(key: str, /, **kw) -> str:
    text = STRINGS.get(_lang, {}).get(key) or STRINGS["en"].get(key) or key
    try:
        return text.format(**kw) if kw else text
    except (KeyError, IndexError):
        return text


def err(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    if reason:
        detail = getattr(exc, "detail", "") or getattr(exc, "message", "") or ""
        text = t(f"e_{reason}", detail=str(detail)[:120])
        if text == f"e_{reason}":
            text = t("e_failed") + (f" ({reason})" if reason else "")
        return text
    if isinstance(exc, OSError):
        return f"{t('e_failed')} ({exc.strerror or exc})"
    return f"{t('e_failed')} ({exc})"
