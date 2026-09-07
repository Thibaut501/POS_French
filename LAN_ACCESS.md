# POS V3 LAN Access

Use this when one computer runs POS V3 and another computer connects to it from the same Wi-Fi or Ethernet network.

## Start the Server

On the main POS computer:

```powershell
cd "C:\Users\Portable\Documents\pos_v3_mauritius_products_left_billing_right (1)\pos_v3_mauritius_professional_dashboard"
.\start-lan-server.ps1
```

The script prints one or more network URLs. On the other computer, open the URL shown under "Other computer on the same Wi-Fi/LAN".

For this computer right now, the likely URL is:

```text
http://192.168.100.3:8080
```

Keep the PowerShell window open while using POS V3.

## If the Other Computer Cannot Connect

Make sure both computers are connected to the same Wi-Fi or Ethernet network.

If Windows Firewall blocks the connection, open PowerShell as Administrator and run:

```powershell
cd "C:\Users\Portable\Documents\pos_v3_mauritius_products_left_billing_right (1)\pos_v3_mauritius_professional_dashboard"
.\start-lan-server.ps1 -OpenFirewall
```

The firewall rule allows TCP port `8080` on Private and Domain network profiles.

If Windows shows this Wi-Fi/Ethernet network as Public, either change the network
profile to Private in Windows Settings, or use this on a trusted network only:

```powershell
.\start-lan-server.ps1 -OpenFirewall -AllowPublicNetwork
```

You can also double-click `open-pos-firewall-admin.bat` and approve the Windows
administrator prompt. It opens the same POS port for the current Public network.

## Use a Different Port

If port `8080` is already used:

```powershell
.\start-lan-server.ps1 -Port 8090
```

Then connect from the other computer with:

```text
http://<main-computer-ip>:8090
```

## Use Only the IP Address

To open POS V3 from the other computer with only the IP address, run POS on port
`80`.

On the main POS computer, double-click:

```text
start-ip-only-server-admin.bat
```

Approve the Windows administrator prompt. Then open this on the other computer:

```text
http://192.168.100.3
```

## Security Notes

Only use this on a trusted local network. Change the default admin password before allowing other computers to connect.
