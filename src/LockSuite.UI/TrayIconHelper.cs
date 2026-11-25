using System;

namespace LockSuite.UI;

/// <summary>
/// Administra el ícono de bandeja del sistema (junto al reloj) usando WinForms NotifyIcon
/// con nombres completamente calificados para evitar colisiones con WPF.
/// </summary>
public sealed class TrayIconHelper : IDisposable
{
    private const int MaxTooltipLength = 63;

    private readonly Action _onOpenRequested;
    private readonly Action _onExitRequested;
    private readonly System.Windows.Forms.ContextMenuStrip _contextMenu;
    private readonly System.Windows.Forms.NotifyIcon _notifyIcon;
    private bool _disposed;

    public TrayIconHelper(Action onOpenRequested, Action onExitRequested)
    {
        _onOpenRequested = onOpenRequested ?? throw new ArgumentNullException(nameof(onOpenRequested));
        _onExitRequested = onExitRequested ?? throw new ArgumentNullException(nameof(onExitRequested));

        _contextMenu = new System.Windows.Forms.ContextMenuStrip();

        var openItem = new System.Windows.Forms.ToolStripMenuItem("Abrir LockSuite");
        openItem.Click += (_, _) => _onOpenRequested();

        var exitItem = new System.Windows.Forms.ToolStripMenuItem("Salir");
        exitItem.Click += (_, _) => _onExitRequested();

        _contextMenu.Items.Add(openItem);
        _contextMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        _contextMenu.Items.Add(exitItem);

        _notifyIcon = new System.Windows.Forms.NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Shield,
            Text = "LockSuite Windows",
            Visible = true,
            ContextMenuStrip = _contextMenu
        };
        _notifyIcon.DoubleClick += (_, _) => _onOpenRequested();
    }

    public void ShowNotification(string title, string message, bool isWarning = false)
    {
        if (_disposed) return;

        string safeTitle = string.IsNullOrWhiteSpace(title) ? "LockSuite Windows" : title;
        string safeMessage = string.IsNullOrWhiteSpace(message) ? "Aviso de LockSuite" : message;
        var icon = isWarning
            ? System.Windows.Forms.ToolTipIcon.Warning
            : System.Windows.Forms.ToolTipIcon.Info;

        _notifyIcon.ShowBalloonTip(6000, safeTitle, safeMessage, icon);
    }

    public void UpdateStatusTooltip(string text)
    {
        if (_disposed) return;

        string safe = text ?? string.Empty;
        if (safe.Length > MaxTooltipLength)
        {
            safe = string.Concat(safe.AsSpan(0, MaxTooltipLength - 3), "...");
        }

        _notifyIcon.Text = safe;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _contextMenu.Dispose();
    }
}
