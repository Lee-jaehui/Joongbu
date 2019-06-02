﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;
using System.Diagnostics;
using Microsoft.Win32;
using System.Net;
using System.Net.Sockets;
using System.Management;
using System.Net.NetworkInformation;
using System.ServiceProcess;

namespace JBU_PRJ1
{
    class Program
    {

        public class global
        {
            public static int rser_len;
        }

        public static string RunCommand(string sender)
        {
            string output = null;
            ProcessStartInfo psi = new ProcessStartInfo();

            psi.FileName = "cmd.exe";
            psi.Arguments = "/C \"" + sender + "\"";

            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;

            Process proc = Process.Start(psi);
            while (true)
            {
                string txt = proc.StandardOutput.ReadLine();
                if (txt == null) break;
                return txt;
            }
            return output;
        }

        public static string GetMotherBoardID()
        {
            string mbInfo = String.Empty;
            ManagementScope scope = new ManagementScope("\\\\" + Environment.MachineName + "\\root\\cimv2");
            scope.Connect();
            ManagementObject wmiClass = new ManagementObject(scope, new ManagementPath("Win32_BaseBoard.Tag=\"Base Board\""), new ObjectGetOptions());

            foreach (PropertyData propData in wmiClass.Properties)
            {
                if (propData.Name == "SerialNumber")
                    mbInfo = String.Format("{0,-25}{1}", propData.Name, Convert.ToString(propData.Value));
            }

            return mbInfo;
        }
        public static string GetOSInfo()
        {
            var name = (from x in new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem").Get().Cast<ManagementObject>()select x.GetPropertyValue("Caption")).FirstOrDefault();
            string r2 = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild", "").ToString();
            string r3 = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", "").ToString();

            String Arch;
            if (Environment.Is64BitOperatingSystem)
            {
                Arch = " x64";
            }
            else
            {
                Arch = " x32";
            }

            string ta = name + Arch + " " + r2 + "." + r3;

            return ta != null ? ta.ToString() : "Unknown";
        }

        public static void ServiceCheck(string name)
        {
            ServiceController sc = new ServiceController(name);
            if (sc.Status.ToString() == "Stopped")
            {
                global.rser_len += 1;
            } 
        }

        public static void Main()
        {
            Console.WriteLine("PC 이름: {0}", Environment.MachineName);
            string r1 = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "").ToString();
            string r2 = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild", "").ToString();
            string r3 = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", "").ToString();
            String sProcess;
            if (Environment.Is64BitOperatingSystem)
            {
                sProcess = "64";
            }
            else
            {
                sProcess = "32";
            }
            Console.WriteLine("OS : " + r1 + " x{0}", sProcess + " " + r2 + "." + r3 + "\n");

            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                var addr = ni.GetIPProperties().GatewayAddresses.FirstOrDefault();
                if (addr != null)
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                    {
                        //Console.WriteLine(ni.Name);
                        foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                Console.WriteLine("IP: " + ip.Address.ToString());
                            }
                        }
                    }
                }
            }

            string maxpwage = RunCommand("net accounts | find \"최대\"");//<90위험
            maxpwage = Regex.Replace(maxpwage, @"\D", "");

            string minpwage = RunCommand("net accounts | find \"암호 사용\"");//<1위험
            minpwage = Regex.Replace(minpwage, @"\D", "");

            string minpwlen = RunCommand("net accounts | find \"길이\"");//<8위험
            minpwlen = Regex.Replace(minpwlen, @"\D", "");

            string uniquepw = RunCommand("net accounts | find \"기록\"");//<2위험
            uniquepw = Regex.Replace(uniquepw, @"\D", "");
            if (uniquepw.Equals("")) { uniquepw = "0"; };

            Console.WriteLine("최대: " + maxpwage + "\n최소: " + minpwage + "\n길이: " + minpwlen + "\n기록: " + uniquepw);

            string[] drives = Environment.GetLogicalDrives();//기본 공유 위함
            for (int i = 0; i < drives.Length; i++) {
                string fs_i = RunCommand("net share | findstr \"기본\" | findstr \"" + drives[i]);
                if (i == 0) Console.WriteLine("윈도우 설치 드라이브(" + drives[0] + ") 기본 공유 사용 중");
                else if (fs_i != "") Console.WriteLine("추가 드라이브(" + drives[i] + ") 기본 공유 사용 중");
            }

            string fs_a = RunCommand("net share | findstr \"관리\" | find \"ADMIN$\"");
            if (fs_a != "") Console.WriteLine("윈도우 관리 목적 공유 사용 중");

            string reload_share = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "AutoShareServer", "").ToString();
            if (reload_share != "0")
            {
                reload_share = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "AutoShareWks", "").ToString();
                if (reload_share != "0") Console.WriteLine("공유 폴더 자동 갱신 사용 중");
            }

            string[] service_check = new string[] { "AppReadiness", "AppMgmt", "bthserv", "PeerDistSvc", "CertPropSvc", "DiagTrack", "MapsBroker", "WdiServiceHost", "WdiSystemHost", "lfsvc", "SharedAccess", "iphlpsvc", "AppVClient", "MSiSCSI", "SmsRouter", "Netlogon", "CscService", "PNRPsvc", "p2psvc", "p2pimsvc", "Spooler", "TermService", "RemoteRegistry", "RpcLocator", "SensorDataService", "SensrSvc", "SensorService", "SCardSvr", "ScDeviceEnum", "SCPolicySvc", "SNMPTRAP", "StorSvc", "lmhosts", "TabletInputService", "TapiSrv", "UevAgentService", "WebClient", "WbioSrvc", "wcncsvc", "WerSvc", "stisvc", "WMPNetworkSvc", "WinRM", "WSearch", "LicenseManager", "icssvc", "SDRSVC", "wisvc", "FrameServer", "WlanSvc", "LanmanWorkstation", "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "defragsvc", "VSS", "wuauserv", "diagsvc", "fhsvc", "svsvc", "W32Time", "WEPHOSTSVC", "WPDBusEnum", "BITS", "wbengine", "CertPropSvc", "Eaphost", "Fax", "lltdsvc", "irmon", "fdPHost", "FDResPub", "XboxGipSvc", "ALG", "IKEEXT", "swprv", "smphost", "RasAuto", "SessionEnv", "TermService", "UmRdpService", "WiaRpc", "workfolderssvc", "AxInstSV", "diagnosticshub.standardcollector.service", "spectrum", "PushToInstall", "NaturalAuthentication", "wlpasvc", "WFDSConMgrSvc", "IpxlatCfgSvc", "WpnService", "DusmSvc", "SharedRealitySvc", "camsvc", "RmSvc", "RetailDemo", "DmEnrollmentSvc", "CDPSvc", "BDESVC", "DPS", "seclogon", "CryptSvc", "Dhcp", "TrkWks", "hidserv", "Dnscache", "EntAppSvc", "WinHttpAutoProxySvc", "DoSvc", "wscsvc" };
            for (int i = 0; i < service_check.Length; i++) ServiceCheck(service_check[i]);
            int service_stop = service_check.Length - global.rser_len;
            Console.WriteLine("[서비스] 위험 서비스: " + service_check.Length + "개 구동: " + global.rser_len + " 정지: " + service_stop);

            try
            {
                string kakaotalk = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KakaoTalk", "UninstallString", "").ToString();
                Console.WriteLine("[메신저] 카카오톡 설치 확인");
            }
            catch
            {
                Console.WriteLine("[메신저] 카카오톡 설치X 확인");
            }
            try
            {
                string kakaotalk = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\LINE", "UninstallString", "").ToString();
                Console.WriteLine("[메신저] 라인 설치 확인");
            }
            catch
            {
                Console.WriteLine("[메신저] 라인 설치X 확인");
            }
            try
            {
                string skype = Registry.GetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Skype_is1", "UninstallString", "").ToString();
                Console.WriteLine("[메신저] Skype 설치 확인");
            }
            catch
            {
                Console.WriteLine("[메신저] Skype 설치X 확인");
            }

            string nateon = Environment.GetEnvironmentVariable("ProgramFiles(x86)")+"\\SK Communications\\NATEON\\BIN\\NateOnMain.exe";
            if (File.Exists(nateon))
            {
                Console.WriteLine("[메신저] 네이트온 설치 확인");
            }
            else
            {
                nateon = Environment.GetEnvironmentVariable("ProgramFiles")+"\\SK Communications\\NATEON\\BIN\\NateOnMain.exe";
                if (File.Exists(nateon))
                {
                    Console.WriteLine("[메신저] 네이트온 설치 확인");
                } else
                {
                    Console.WriteLine("[메신저] 네이트온 설치X 확인");
                }
            }
            
            string r4 = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", "").ToString();
            if(Convert.ToInt32(r4) >= 1) Console.WriteLine("[OS] 방화벽 사용 중");
            //HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall{697E41EA-AEBE-4B5F-884E-87B5CD6C70AC}
            //HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall{EA77EC9A-C82F-4F80-8B7D-D32C09A9C25F}

            Console.ReadLine();
        }
    }
}
