using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Terminal.Gui;

namespace netstatExtendedTUIv2
{
    internal class Program
    {
        private static Dictionary<int, string> knownPorts = new Dictionary<int, string>
        {
    //СЕТЕВЫЕ КОМПОНЕНТЫ
            // Windows system ports
            { 135, "RPC (Remote Procedure Call)" },
            { 137, "NetBIOS Name Service" },
            { 138, "NetBIOS Datagram Service" },
            { 139, "NetBIOS Session Service (SMB over NetBIOS)" },
            { 445, "Microsoft-DS (SMB over TCP)" },
            { 593, "RPC over HTTP" },
            { 3389, "RDP (Remote Desktop Protocol)" },
            
            // Databases
            { 1433, "Microsoft SQL Server" },
            { 1434, "Microsoft SQL Monitor" },
            { 1521, "Oracle Database" },
            { 1522, "Oracle Database" },
            { 1525, "Oracle Database" },
            { 3306, "MySQL Database" },
            { 5432, "PostgreSQL" },
            { 27017, "MongoDB" },
            { 27018, "MongoDB Sharding" },
            { 27019, "MongoDB" },
            { 5984, "CouchDB" },
            { 6379, "Redis" },
            { 9200, "Elasticsearch" },
            { 9300, "Elasticsearch Cluster" },
            
            // Web servers
            { 80, "HTTP" },
            { 443, "HTTPS" },
            { 8080, "HTTP Alternative/Proxy" },
            { 8443, "HTTPS Alternative" },
            { 8888, "HTTP Alternative" },
            { 8000, "HTTP Alternative/Django/Development" },
            { 3000, "Node.js/React/Grafana" },
            { 5000, "Flask/Development/Synology DSM" },
            
            // File protocols
            { 21, "FTP" },
            { 22, "SSH" },
            { 23, "Telnet [unsafe]" },
            { 69, "TFTP" },
            { 2049, "NFS" },
            { 873, "rsync" },
            
            // Mail protocols
            { 25, "SMTP" },
            { 110, "POP3" },
            { 143, "IMAP" },
            { 465, "SMTPS" },
            { 587, "SMTP Submission" },
            { 993, "IMAPS" },
            { 995, "POP3S" },
            
            // Remote access
            { 5900, "VNC" },
            { 5901, "VNC" },
            { 5800, "VNC over HTTP" },
            { 5801, "VNC over HTTP" },
            { 5190, "AOL/ICQ" },
            
            // Game servers
            { 27015, "Steam/CS:GO" },
            { 25565, "Minecraft" },
            { 7777, "Unreal Tournament" },
            { 28960, "Call of Duty" },
            
            // Virtualization
            { 902, "VMware ESXi" },
            { 903, "VMware ESXi" },
            { 2375, "Docker [unsafe]" },
            { 2376, "Docker TLS" },
            
            // Network protocols
            { 53, "DNS" },
            { 67, "DHCP Server" },
            { 68, "DHCP Client" },
            { 161, "SNMP" },
            { 162, "SNMP Trap" },
            { 389, "LDAP" },
            { 636, "LDAPS" },
            { 1812, "RADIUS Authentication" },
            { 1813, "RADIUS Accounting" },
            
            // Dangerous ports
            { 4444, "Meterpreter" },
            { 31337, "Back Orifice" },
            { 666, "Doom/IRC" },
            { 1337, "Backdoor" },
            { 12345, "NetBus" },
            { 12346, "NetBus" },
            { 20034, "NetBus Pro" },
            { 27374, "SubSeven" },
            { 54320, "Back Orifice 2000" },
            { 54321, "Back Orifice 2000" },
            
            // Media servers
            { 32400, "Plex Media Server" },
            { 1900, "UPnP/SSDP" },
            { 5001, "Synology DSM" },
            
            // IoT
            { 1883, "MQTT" },
            { 8883, "MQTTS" },
            { 5683, "CoAP" },
            { 5684, "CoAPS" },
            
            // Monitoring
            { 9090, "Prometheus" },
            { 9093, "Alertmanager" },
            { 9100, "Node Exporter" },
            
            // Containers and orchestration
            { 6443, "Kubernetes API" },
            { 10250, "Kubelet API" },
            { 10255, "Kubelet Read-Only" },
            { 10256, "kube-proxy" },
            { 2379, "etcd Client" },
            { 2380, "etcd Peer" },
            
            // Other
            { 514, "Syslog" },
            { 1194, "OpenVPN" },
            { 1723, "PPTP" },
            { 1701, "L2TP" },
            { 5060, "SIP" },
            { 5061, "SIPS" },
            { 5222, "XMPP/Jabber" },
            { 5269, "XMPP Server-to-Server" },
            { 6667, "IRC" },
            { 6697, "IRC over SSL" },
            { 10000, "Webmin" }
        };

    private static bool IsDangerousPort(int port)
    {
        int[] dangerousPorts = { 135, 137, 138, 139, 445, 1433, 1434, 22, 23, 3389, 5900 };
        return dangerousPorts.Contains(port);
    }

    //КОМПОНЕНТЫ
    private static Window _tcpWindow;
    private static Window _portsWindow;
    private static Window _currentWindow;

    private static TextView _tcpTextView;
    private static TextView _portsTextView;

    private static Button _refreshTcpButton;
    private static Button _refreshPortsButton;

    private static bool _monitoringActive = false;
    private static Thread _monitoringThread;

    //МЕТОДЫ ВЫВОДА СЕТЕВОЙ ИНФОРМАЦИИ 

    private static string GetStateWithIcon(TcpState state)
    {
        switch (state)
        {
            case TcpState.Established:
                return "Установлено";
            case TcpState.Listen:
                return "Ожидание";
            case TcpState.TimeWait:
                return "Ожидание";
            case TcpState.CloseWait:
                return "Закрытие";
            case TcpState.Closing:
                return "Закрыто";
            default:
                return state.ToString();
        }
    }

    private static string GetTcpConnectionsString()
    {
        var sb = new StringBuilder();
        sb.AppendLine("╔══════════════════════════════════════════════════════════╗");
        sb.AppendLine("║                    АКТИВНЫЕ TCP СОЕДИНЕНИЯ               ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════╝\n");

        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var connections = properties.GetActiveTcpConnections();

            sb.AppendLine($"Всего соединений: {connections.Length}");
            sb.AppendLine("─".PadRight(80, '─'));
            sb.AppendLine("ЛОКАЛЬНЫЙ АДРЕС".PadRight(25) + " │ " +
                          "ВНЕШНИЙ АДРЕС".PadRight(25) + " │ СОСТОЯНИЕ");
            sb.AppendLine("─".PadRight(80, '─'));

            foreach (var conn in connections.Take(50))
            {
                string state = GetStateWithIcon(conn.State);
                sb.AppendLine($"{conn.LocalEndPoint.ToString().PadRight(25)} │ " +
                              $"{conn.RemoteEndPoint.ToString().PadRight(25)} │ {state}");
            }

            if (connections.Length > 50)
                sb.AppendLine($"\n... и еще {connections.Length - 50} соединений");
        }
        catch (Exception ex)
        {
            sb.AppendLine($"Ошибка: {ex.Message}");
        }

        return sb.ToString();
    }

    private static string GetKnownPortsString()
    {
        var sb = new StringBuilder();
        sb.AppendLine("╔══════════════════════════════════════════════════════════╗");
        sb.AppendLine("║               ИЗВЕСТНЫЕ И ОПАСНЫЕ ПОРТЫ                  ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════╝\n");

        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            sb.AppendLine("TCP СЛУШАТЕЛИ:");
            sb.AppendLine("─".PadRight(80, '─'));
            var tcpListeners = properties.GetActiveTcpListeners();
            foreach (var endpoint in tcpListeners)
            {
                if (knownPorts.TryGetValue(endpoint.Port, out string service))
                {
                    bool dangerous = IsDangerousPort(endpoint.Port);
                    string marker = dangerous ? " !" : "  ";
                    sb.AppendLine($"{marker}{endpoint.Port,-6} {endpoint.Address,-20} {service}");
                }
            }

            sb.AppendLine("\n" + "─".PadRight(80, '─'));

            sb.AppendLine("\nUDP СЛУШАТЕЛИ:");
            sb.AppendLine("─".PadRight(80, '─'));
            var udpListeners = properties.GetActiveUdpListeners();
            foreach (var endpoint in udpListeners)
            {
                if (knownPorts.TryGetValue(endpoint.Port, out string service))
                {
                    bool dangerous = IsDangerousPort(endpoint.Port);
                    string marker = dangerous ? " !" : "  ";
                    sb.AppendLine($"{marker}{endpoint.Port,-6} {endpoint.Address,-20} {service}");
                }
            }

            sb.AppendLine("\n" + "═".PadRight(80, '═'));
            var udpStats = properties.GetUdpIPv4Statistics();
            sb.AppendLine($"СТАТИСТИКА UDP:");
            sb.AppendLine($"Получено пакетов: {udpStats.DatagramsReceived}");
            sb.AppendLine($"Отправлено пакетов: {udpStats.DatagramsSent}");
        }
        catch (Exception ex)
        {
            sb.AppendLine($"Ошибка: {ex.Message}");
        }

        return sb.ToString();
    }

    //МЕТОДЫ ОБНОВЛЕНИЯ UI 

    private static void UpdateTcpWindow()
    {
        string tcpInfo = GetTcpConnectionsString();
        Application.MainLoop.Invoke(() => {
            _tcpTextView.Text = tcpInfo;
            _tcpTextView.SetNeedsDisplay();
        });
    }

    private static void UpdatePortsWindow()
    {
        string portsInfo = GetKnownPortsString();
        Application.MainLoop.Invoke(() => {
            _portsTextView.Text = portsInfo;
            _portsTextView.SetNeedsDisplay();
        });
    }

    //ФОНОВЫЙ МОНИТОРИНГ 

    private static void StartMonitoring()
    {
        _monitoringActive = true;
        _monitoringThread = new Thread(() => {
            while (_monitoringActive)
            {
                UpdateTcpWindow();
                UpdatePortsWindow();
                Thread.Sleep(3000);
            }
        });
        _monitoringThread.Start();
    }

    private static void StopMonitoring()
    {
        _monitoringActive = false;
        _monitoringThread?.Join(1000);
    }


        private static ColorScheme CreateDarkColorScheme()
        {
            //Создаём новую схему
            var scheme = new ColorScheme();
            //Основные цвета (текст белый, фон тёмно-серый)
            scheme.Normal = Terminal.Gui.Attribute.Make(Color.White, Color.Black);
            //Цвт для "горячих" клавиш (подчёркнутых в меню)
            scheme.HotNormal = Terminal.Gui.Attribute.Make(Color.BrightYellow, Color.Black);
            //Цвет элемента в фокусе (текст чёрный, фон голубой)
            scheme.Focus = Terminal.Gui.Attribute.Make(Color.Black, Color.DarkGray);
            //Цвет "горячего" элемента в фокусе
            scheme.HotFocus = Terminal.Gui.Attribute.Make(Color.BrightMagenta, Color.DarkGray);

            return scheme;
        }

        //ОСНОВНОЙ КОД TUI

        static void Main(string[] args)
    {
        Application.Init();
        ColorScheme darkScheme = CreateDarkColorScheme();



            var menu = new MenuBar(new MenuBarItem[] {
                new MenuBarItem("_Файл", new MenuItem[] {
                    new MenuItem("_Обновить всё", "", () => {
                        UpdateTcpWindow();
                        UpdatePortsWindow();
                    }),
                    new MenuItem("_Выход", "", () => {
                        StopMonitoring();
                        Application.RequestStop();
                    })
                }),
                new MenuBarItem("_Окна", new MenuItem[] {
                    new MenuItem("_TCP Монитор", "", () => SwitchToWindow(_tcpWindow)),
                    new MenuItem("_Порты", "", () => SwitchToWindow(_portsWindow)),
                    new MenuItem("_Разделить", "", () => ShowBothWindows())
                }),
                new MenuBarItem("_Справка", new MenuItem[] {
                    new MenuItem("_О программе", "", () =>
                        MessageBox.Query("netstatExtendedTUI",
                            "Монитор сетевых соединений v1.2\n" +
                            "TCP соединения + Анализ портов\n" +
                            "© 2025 Автор: Aksik", "OK"))
                })
            });

        //Окно TCP мониторинга
        _tcpWindow = new Window("TCP Мониторинг")
        {
            X = 0,
            Y = 1,
            Width = Dim.Fill(),
            Height = Dim.Fill(),
            ColorScheme = darkScheme
        };

        _refreshTcpButton = new Button("Обновить")
        {
            X = Pos.Center(),
            Y = 1,
            ColorScheme = darkScheme
        };
        _refreshTcpButton.Clicked += () => UpdateTcpWindow();

        _tcpTextView = new TextView()
        {
            X = 0,
            Y = 3,
            Width = Dim.Fill(),
            Height = Dim.Fill() - 1,
            ReadOnly = true,
            WordWrap = false,
            ColorScheme = darkScheme
        };

        _tcpWindow.Add(
            new Label("Режим реального времени (обновление каждые 3 сек):")
            {
                X = 2,
                Y = 0,
                ColorScheme = darkScheme
            },
            _refreshTcpButton,
            _tcpTextView

        );

        //Окно анализа портов
        _portsWindow = new Window("Анализ портов")
        {
            X = 0,
            Y = 1,
            Width = Dim.Fill(),
            Height = Dim.Fill(),
            Visible = false,
            ColorScheme = darkScheme
        };

        _refreshPortsButton = new Button("Обновить")
        {
            X = Pos.Center(),
            Y = 1,
            ColorScheme = darkScheme
        };
        _refreshPortsButton.Clicked += () => UpdatePortsWindow();

        _portsTextView = new TextView()
        {
            X = 0,
            Y = 3,
            Width = Dim.Fill(),
            Height = Dim.Fill() - 1,
            ReadOnly = true,
            WordWrap = false,

        };

        _portsWindow.Add(
            new Label("Опасные порты помечены [ ! ]:") { X = 2, Y = 0 },
            _refreshPortsButton,
            _portsTextView
        );

        _currentWindow = _tcpWindow;

        var top = Application.Top;
        top.Add(menu, _tcpWindow, _portsWindow);

        UpdateTcpWindow();
        UpdatePortsWindow();

        StartMonitoring();

        Application.Run(top);

        StopMonitoring();
        Application.Shutdown();
    }

    //МЕТОДЫ УПРАВЛЕНИЯ ОКНАМИ 

    private static void SwitchToWindow(Window windowToShow)
    {
        if (windowToShow == _currentWindow) return;

        _currentWindow.Visible = false;
        windowToShow.Visible = true;
        _currentWindow = windowToShow;

        Application.Top.SetNeedsDisplay();
    }

    private static void ShowBothWindows()
    {
        _tcpWindow.X = 0;
        _tcpWindow.Y = 1;
        _tcpWindow.Width = Dim.Percent(50);
        _tcpWindow.Height = Dim.Fill();
        _tcpWindow.Visible = true;

        _portsWindow.X = Pos.Percent(50);
        _portsWindow.Y = 1;
        _portsWindow.Width = Dim.Percent(50);
        _portsWindow.Height = Dim.Fill();
        _portsWindow.Visible = true;

        _currentWindow = _tcpWindow;
        Application.Top.SetNeedsDisplay();
    }
}
}

