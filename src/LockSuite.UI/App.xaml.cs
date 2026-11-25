using System;
using System.Threading;
using System.Windows;

namespace LockSuite.UI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    private Mutex? _singleInstanceMutex;
    private bool _ownsMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        _singleInstanceMutex = new Mutex(initiallyOwned: true, @"Local\LockSuite_UI_SingleInstance", out bool createdNew);
        _ownsMutex = createdNew;

        if (!createdNew)
        {
            _singleInstanceMutex.Dispose();
            _singleInstanceMutex = null;

            MessageBox.Show(
                "LockSuite ya está abierto. Revisá la barra de tareas o el ícono junto al reloj.",
                "LockSuite Windows",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            Shutdown(0);
            return;
        }

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_singleInstanceMutex != null)
        {
            if (_ownsMutex)
            {
                try { _singleInstanceMutex.ReleaseMutex(); }
                catch (ApplicationException) { }
            }

            _singleInstanceMutex.Dispose();
            _singleInstanceMutex = null;
        }

        base.OnExit(e);
    }
}

