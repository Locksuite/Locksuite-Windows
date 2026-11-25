using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using LockSuite.Core;
using LockSuite.UI.ViewModels;
using LockSuite.UI.Views;

namespace LockSuite.UI;

public partial class MainWindow : Window
{
    private MainViewModel ViewModel => (MainViewModel)DataContext;
    private TrayIconHelper? _trayIcon;
    private bool _trialHandling;
    private bool _wasDnsDown;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnWindowLoaded;
    }

    private void OnWindowLoaded(object sender, RoutedEventArgs e)
    {
        if (_trayIcon == null)
        {
            _trayIcon = new TrayIconHelper(RestoreFromTray, ExitFromTray);
            _trayIcon.UpdateStatusTooltip($"LockSuite — {ViewModel.StatusMessage}");
        }

        _wasDnsDown = ViewModel.IsDnsDown;
        ViewModel.TrialAwaitingDecision += OnTrialAwaiting;
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    protected override void OnClosed(EventArgs e)
    {
        ViewModel.TrialAwaitingDecision -= OnTrialAwaiting;
        ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        _trayIcon?.Dispose();
        _trayIcon = null;
        base.OnClosed(e);
    }

    private void RestoreFromTray()
    {
        Dispatcher.Invoke(() =>
        {
            if (!IsVisible) Show();
            if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Activate();
            Topmost = true;
            Topmost = false;
            Focus();
        });
    }

    private void ExitFromTray()
    {
        Dispatcher.Invoke(() => Application.Current.Shutdown());
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.IsDnsDown))
        {
            bool isDnsDown = ViewModel.IsDnsDown;
            if (isDnsDown && !_wasDnsDown)
            {
                _trayIcon?.ShowNotification(
                    "Resolutor DNS detenido",
                    "El puerto 53 está ocupado por otro programa. La red sigue bloqueada hasta resolverlo.",
                    isWarning: true);
            }
            _wasDnsDown = isDnsDown;
        }
        else if (e.PropertyName == nameof(MainViewModel.StatusMessage))
        {
            _trayIcon?.UpdateStatusTooltip($"LockSuite — {ViewModel.StatusMessage}");
        }
    }

    private void NavButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton btn && btn.Tag is string tag)
        {
            ViewEstado.Visibility = tag == "Estado" ? Visibility.Visible : Visibility.Collapsed;
            ViewListaBlanca.Visibility = tag == "ListaBlanca" ? Visibility.Visible : Visibility.Collapsed;
            ViewRecientes.Visibility = tag == "Recientes" ? Visibility.Visible : Visibility.Collapsed;
            ViewConfig.Visibility = tag == "Configuracion" ? Visibility.Visible : Visibility.Collapsed;
            ViewAyuda.Visibility = tag == "Ayuda" ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private async void BtnRefresh_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.RefreshDataAsync();
    }

    private async void BtnAuthTutor_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.IsAuthenticated)
        {
            await ViewModel.LockTutorAsync();
            MessageBox.Show(this, "Sesión de tutor bloqueada. Los cambios quedan restringidos.", "Sesión Cerrada", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        using (ViewModel.PauseRefresh())
        {
            await EnsureAuthenticatedAsync();
        }
    }

    private async Task<bool> EnsureAuthenticatedAsync()
    {
        if (ViewModel.IsAuthenticated) return true;

        if (!ViewModel.IsPasswordConfigured)
        {
            var initDlg = new PasswordDialog
            {
                Owner = this,
                Title = "Configurar Contraseña Maestra Inicial"
            };
            if (initDlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(initDlg.Password))
            {
                var (initSuccess, initErr) = await ViewModel.SetInitialPasswordAsync(initDlg.Password);
                if (initSuccess)
                {
                    await ViewModel.AuthenticateTutorAsync(initDlg.Password);
                    MessageBox.Show(this, "Contraseña maestra configurada exitosamente.", "Éxito", MessageBoxButton.OK, MessageBoxImage.Information);
                    return true;
                }
                else
                {
                    MessageBox.Show(this, initErr ?? "No se pudo configurar la contraseña", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }
            }
            return false;
        }

        var dlg = new PasswordDialog { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            var (success, error) = await ViewModel.AuthenticateTutorAsync(dlg.Password);
            if (success)
            {
                return true;
            }
            else
            {
                MessageBox.Show(this, error ?? "Contraseña incorrecta", "Autenticación Denegada", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
        }

        return false;
    }

    private async Task HandleMutationFailureAsync(bool sessionExpired, string? error, string fallbackMessage)
    {
        if (sessionExpired)
        {
            MessageBox.Show(this,
                error ?? "La sesión del tutor expiró. Volvé a autenticarte para aplicar cambios.",
                "Sesión Expirada", MessageBoxButton.OK, MessageBoxImage.Warning);
            using (ViewModel.PauseRefresh())
            {
                await EnsureAuthenticatedAsync();
            }
            return;
        }

        MessageBox.Show(this, error ?? fallbackMessage, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private async void ChkPackToggle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox chk && chk.DataContext is PackViewModel pack)
        {
            bool desired = chk.IsChecked == true;

            using (ViewModel.PauseRefresh())
            {
                if (!await EnsureAuthenticatedAsync())
                {
                    chk.IsChecked = !desired; // Revertir check
                    pack.Enabled = !desired;
                    return;
                }

                // Desactivar un paquete de bloqueo (p. ej. el del buscador de Google y Gemini) pide confirmación.
                if (pack.Blocks && !desired)
                {
                    var confirm = MessageBox.Show(this,
                        $"Vas a desactivar «{pack.Name}».\n\nMientras esté desactivado, esos sitios dejan de estar bloqueados si algún paquete los permite (por ejemplo, el buscador de Google o Gemini).\n\n¿Continuar?",
                        "Desactivar bloqueo", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    if (confirm != MessageBoxResult.Yes)
                    {
                        chk.IsChecked = true;
                        pack.Enabled = true;
                        return;
                    }
                }
            }

            var (ok, expired, err) = await ViewModel.TogglePackDetailedAsync(pack);
            if (!ok)
            {
                chk.IsChecked = !desired;
                pack.Enabled = !desired;
                await HandleMutationFailureAsync(expired, err, "Error al actualizar el estado del paquete");
            }
        }
    }

    // ----------------- Servicios con un clic ("Permitir Gmail", etc.) -----------------

    private async void BtnServiceToggle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.DataContext is not PackViewModel pack) return;

        using (ViewModel.PauseRefresh())
        {
            if (!await EnsureAuthenticatedAsync()) return;
        }

        bool previous = pack.Enabled;
        pack.Enabled = !previous;   // TogglePackDetailedAsync envía el estado nuevo

        var (ok, expired, err) = await ViewModel.TogglePackDetailedAsync(pack);
        if (!ok)
        {
            pack.Enabled = previous;
            await HandleMutationFailureAsync(expired, err,
                $"No se pudo actualizar «{pack.Title}». Verificá que el servicio LockSuite esté en ejecución.");
            return;
        }

        if (pack.Enabled)
        {
            MessageBox.Show(this,
                $"{pack.Title} quedó permitido.\n\nSi el navegador ya tenía la página abierta, recargala (F5). " +
                "El buscador de Google y Gemini siguen bloqueados.",
                "Servicio permitido", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show(this,
                $"{pack.Title} quedó bloqueado.\n\nLo que ya estaba abierto puede seguir funcionando unos minutos " +
                "(hasta que venzan la caché de DNS y la autorización temporal).",
                "Servicio bloqueado", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void BtnServiceOpen_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string url) return;

        // Solo direcciones https del catálogo de servicios.
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps) return;

        try
        {
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"No se pudo abrir el navegador: {ex.Message}\n\nDirección: {uri.AbsoluteUri}",
                "Abrir servicio", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void BtnAddDomain_Click(object sender, RoutedEventArgs e)
    {
        string domain;
        string? selectedPack;

        using (ViewModel.PauseRefresh())
        {
            if (!await EnsureAuthenticatedAsync()) return;

            // Solo paquetes del tutor: los de fábrica se manejan con sus botones y los de bloqueo no reciben permisos.
            var existingPacks = ViewModel.CustomPackNames();
            var dlg = new AddDomainDialog(existingPacks) { Owner = this };

            if (dlg.ShowDialog() != true) return;

            // Aviso si el patrón abarca el buscador de Google o Gemini (p. ej. "google.com").
            if (Presets.CoversKosherBlockedSites(dlg.Domain))
            {
                var confirm = MessageBox.Show(this,
                    $"«{dlg.Domain}» abarca el buscador de Google y/o Gemini.\n\n" +
                    "Esas partes van a seguir bloqueadas por el «Bloqueo fijo» mientras esté activo, pero se habilitarían muchos otros servicios de Google (Play, Noticias, Mapas, etc.).\n\n" +
                    "Para Gmail, Chat, Drive y Fotos conviene usar sus botones en «Lista Blanca». ¿Agregar igual?",
                    "Dominio muy amplio", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (confirm != MessageBoxResult.Yes) return;
            }

            domain = dlg.Domain;
            selectedPack = dlg.SelectedPack;
        }

        var (ok, expired, err) = await ViewModel.AddDomainDetailedAsync(domain, selectedPack);
        if (ok)
        {
            MessageBox.Show(this, $"Dominio '{domain}' agregado a la lista blanca.", "Dominio Agregado", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            await HandleMutationFailureAsync(expired, err, "No se pudo agregar el dominio.");
        }
    }

    private async void BtnRemoveDomain_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string domain)
        {
            using (ViewModel.PauseRefresh())
            {
                if (!await EnsureAuthenticatedAsync()) return;

                string normalizedTarget = DomainMatcher.Normalize(domain);
                bool inBlockPack = ViewModel.Packs.Any(p => p.Blocks &&
                    p.Domains.Any(d => string.Equals(DomainMatcher.Normalize(d), normalizedTarget, StringComparison.OrdinalIgnoreCase)));
                string question = inBlockPack
                    ? $"«{domain}» está en un paquete de bloqueo. Si lo quitás, deja de estar bloqueado cuando algún paquete lo permita.\n\n¿Quitarlo del bloqueo?"
                    : $"¿Seguro que desea eliminar '{domain}' de la lista blanca?\n\n(Se quita de todos los paquetes donde aparece. Se puede volver a agregar con «+ Agregar Dominio».)";
                var result = MessageBox.Show(this, question, "Confirmar Eliminación", MessageBoxButton.YesNo,
                    inBlockPack ? MessageBoxImage.Warning : MessageBoxImage.Question);
                if (result != MessageBoxResult.Yes) return;
            }

            var (ok, expired, err) = await ViewModel.RemoveDomainDetailedAsync(domain);
            if (!ok)
            {
                await HandleMutationFailureAsync(expired, err, "No se pudo eliminar el dominio.");
            }
        }
    }

    private async void BtnAllowBlocked_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string domain)
        {
            // Lo que está en un bloqueo fijo (buscador de Google, Gemini) no se habilita agregándolo a la lista.
            if (ViewModel.IsHardBlocked(domain))
            {
                MessageBox.Show(this,
                    $"«{domain}» está bloqueado a propósito por un paquete de bloqueo (por ejemplo, «Bloqueo fijo: buscador de Google y Gemini»).\n\n" +
                    "Agregarlo a la lista blanca no lo habilitaría. Si de verdad hace falta, primero hay que desactivar ese bloqueo en «Lista Blanca».",
                    "Bloqueo fijo", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            using (ViewModel.PauseRefresh())
            {
                if (!await EnsureAuthenticatedAsync()) return;
            }

            var (ok, expired, err) = await ViewModel.AddDomainDetailedAsync(domain, Presets.CustomPackName);
            if (ok)
            {
                MessageBox.Show(this, $"El dominio '{domain}' ha sido permitido y agregado a la lista blanca.", "Dominio Permitido", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                await HandleMutationFailureAsync(expired, err, "No se pudo autorizar el dominio.");
            }
        }
    }

    private async void BtnClearBlocked_Click(object sender, RoutedEventArgs e)
    {
        using (ViewModel.PauseRefresh())
        {
            if (!await EnsureAuthenticatedAsync()) return;
        }

        var (ok, expired, err) = await ViewModel.ClearRecentBlockedDetailedAsync();
        if (ok)
        {
            MessageBox.Show(this, "Historial de dominios bloqueados vaciado.", "Historial Limpio", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            await HandleMutationFailureAsync(expired, err, "No se pudo vaciar el historial.");
        }
    }

    private async void BtnChangePassword_Click(object sender, RoutedEventArgs e)
    {
        string oldPassword;
        string newPassword;

        using (ViewModel.PauseRefresh())
        {
            if (!await EnsureAuthenticatedAsync()) return;

            var dlgOld = new PasswordDialog
            {
                Owner = this,
                Title = "Confirmar Contraseña Actual"
            };
            if (dlgOld.ShowDialog() != true) return;

            var dlgNew = new PasswordDialog
            {
                Owner = this,
                Title = "Nueva Contraseña Maestra"
            };
            if (dlgNew.ShowDialog() != true) return;

            if (dlgNew.Password.Length < 6)
            {
                MessageBox.Show(this, "La nueva contraseña debe tener al menos 6 caracteres.", "Contraseña Inválida", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dlgConfirm = new PasswordDialog
            {
                Owner = this,
                Title = "Confirmar Nueva Contraseña Maestra"
            };
            if (dlgConfirm.ShowDialog() != true) return;

            if (!string.Equals(dlgNew.Password, dlgConfirm.Password, StringComparison.Ordinal))
            {
                MessageBox.Show(this, "Las contraseñas nuevas no coinciden.", "Error de Confirmación", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            oldPassword = dlgOld.Password;
            newPassword = dlgNew.Password;
        }

        var (success, error) = await ViewModel.ChangePasswordAsync(oldPassword, newPassword);
        if (success)
        {
            MessageBox.Show(this, "Contraseña maestra actualizada exitosamente.", "Éxito", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show(this, error ?? "Error al cambiar contraseña", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void BtnTestWfp_Click(object sender, RoutedEventArgs e)
    {
        using (ViewModel.PauseRefresh())
        {
            if (!await EnsureAuthenticatedAsync()) return;
        }

        string result = await ViewModel.RunWfpTestAsync();
        MessageBox.Show(this, result, "Estado de Filtros WFP", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async Task HandlePolicyCheckBoxClickAsync(
        CheckBox chk,
        Func<bool, Task<(bool Success, bool SessionExpired, string? Error)>> mutation,
        string errorFallback)
    {
        bool desired = chk.IsChecked == true;

        using (ViewModel.PauseRefresh())
        {
            if (!await EnsureAuthenticatedAsync())
            {
                chk.IsChecked = !desired;
                return;
            }
        }

        var (ok, expired, err) = await mutation(desired);
        if (!ok)
        {
            chk.IsChecked = !desired;
            await HandleMutationFailureAsync(expired, err, errorFallback);
        }
    }

    private async void ChkLearningMode_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox chk)
        {
            await HandlePolicyCheckBoxClickAsync(
                chk,
                ViewModel.SetLearningModeDetailedAsync,
                "No se pudo cambiar el modo aprendizaje.");
        }
    }

    private async void ChkAllowLocalNetwork_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox chk)
        {
            await HandlePolicyCheckBoxClickAsync(
                chk,
                ViewModel.SetAllowLocalNetworkDetailedAsync,
                "No se pudo cambiar el permiso de red local.");
        }
    }

    private async void ChkSniInspection_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox chk)
        {
            await HandlePolicyCheckBoxClickAsync(
                chk,
                ViewModel.SetSniInspectionDetailedAsync,
                "No se pudo cambiar la inspección SNI.");
        }
    }

    // ----------------- Wi-Fi de hotel / portal cautivo -----------------

    private async void BtnCaptivePortal_Click(object sender, RoutedEventArgs e)
    {
        using (ViewModel.PauseRefresh())
        {
            if (!await EnsureAuthenticatedAsync()) return;

            var confirm = MessageBox.Show(this,
                "Se abrirá una ventana de 5 minutos para que puedas entrar a la página de la red Wi-Fi (la de aceptar términos o poner la clave).\n\n" +
                "Durante esa ventana se abre solo la red local, no internet: los sitios bloqueados siguen bloqueados. Al terminar, el filtro vuelve solo.\n\n¿Continuar?",
                "Modo portal cautivo", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;
        }

        var (ok, expired, err) = await ViewModel.StartCaptivePortalDetailedAsync(5);
        if (ok)
        {
            MessageBox.Show(this,
                "Listo. Abrí el navegador: debería aparecer la página de la red Wi-Fi. Si no aparece sola, entrá a cualquier dirección y la red te va a redirigir.",
                "Modo portal cautivo activo", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else if (expired)
        {
            await HandleMutationFailureAsync(expired, err, "No se pudo abrir el modo portal cautivo.");
        }
        else
        {
            MessageBox.Show(this, err ?? "No se pudo abrir el modo portal cautivo.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void BtnCaptivePortalEnd_Click(object sender, RoutedEventArgs e)
    {
        using (ViewModel.PauseRefresh())
        {
            if (!await EnsureAuthenticatedAsync()) return;
        }

        var (ok, expired, err) = await ViewModel.EndCaptivePortalDetailedAsync();
        if (!ok)
        {
            await HandleMutationFailureAsync(expired, err, "No se pudo cerrar el modo portal cautivo.");
        }
    }

    // ----------------- Modo de prueba (trial) -----------------

    private void OnTrialAwaiting()
    {
        _trayIcon?.ShowNotification(
            "Período de prueba terminado",
            "Elegí si conservar LockSuite de forma permanente o quitarlo.",
            isWarning: true);

        // La prueba venció: mostrar el diálogo (en el hilo de UI).
        _ = Dispatcher.InvokeAsync(ShowTrialDialogAsync);
    }

    private async Task ShowTrialDialogAsync()
    {
        if (_trialHandling) return;
        _trialHandling = true;
        try
        {
            using (ViewModel.PauseRefresh())
            {
                var dlg = new TrialEndedDialog(ViewModel.TrialRequireTutorToRemove) { Owner = this };
                bool? r = dlg.ShowDialog();
                if (r == true)
                {
                    await DoTrialKeepAsync();
                }
                else if (dlg.RemoveRequested)
                {
                    await DoTrialRemoveAsync();
                }
                // Si cerró el diálogo sin decidir, el banner en "Estado" queda disponible para decidir luego.
            }
        }
        finally
        {
            _trialHandling = false;
        }
    }

    private async void BtnTrialKeep_Click(object sender, RoutedEventArgs e) => await DoTrialKeepAsync();

    private async void BtnTrialRemove_Click(object sender, RoutedEventArgs e) => await DoTrialRemoveAsync();

    private async Task DoTrialKeepAsync()
    {
        var (ok, err) = await ViewModel.DecideTrialAsync(true, null);
        if (ok)
        {
            MessageBox.Show(this, "LockSuite quedará instalado de forma permanente en este equipo. A partir de ahora, solo el administrador podrá quitarlo.", "LockSuite conservado", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show(this, err ?? "No se pudo registrar la decisión.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task DoTrialRemoveAsync()
    {
        using (ViewModel.PauseRefresh())
        {
            var confirm = MessageBox.Show(this,
                "Se desinstalará LockSuite por completo y se restaurará el acceso a internet sin filtro. ¿Continuar?",
                "Quitar LockSuite", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            string? token = null;
            if (ViewModel.TrialRequireTutorToRemove)
            {
                // La prueba se configuró para exigir la contraseña del tutor al quitar.
                if (!await EnsureAuthenticatedAsync()) return;
                token = ViewModel.SessionToken;
            }

            var (ok, err) = await ViewModel.DecideTrialAsync(false, token);
            if (ok)
            {
                MessageBox.Show(this, "LockSuite se está quitando de este equipo. La aplicación se cerrará.", "Quitando LockSuite", MessageBoxButton.OK, MessageBoxImage.Information);
                Application.Current.Shutdown();
            }
            else
            {
                MessageBox.Show(this, err ?? "No se pudo quitar LockSuite.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
