# Cisco Packet Tracer Lab Guide for NetSage AI

This guide explains how to construct the **NetSage AI Enterprise Network Topology** in Cisco Packet Tracer and save it as a native `.pkt` file.

---

## 1. Why NetSage AI and .pkt Files are Different

- **NetSage AI** is a **Python & Streamlit AI diagnostic web application** that parses Cisco `show` command outputs, diagnoses network faults, and generates verified fixes.
- **`.pkt`** is Cisco's **proprietary simulation file format** created and opened exclusively inside the Cisco Packet Tracer application. Software source code cannot be run inside a `.pkt` file; rather, NetSage AI is the intelligence tool used *alongside* Packet Tracer to solve network issues in the lab.

---

## 2. Topology Diagram

```
                        +--------------------+
                        |     Router R1      |
                        |   Core / Gateway   |
                        +---------+----------+
                                  | Gi0/1 (10.0.0.1/30)
                                  |
                                  | Gi0/0 (10.0.0.2/30)
                                  v
                        +--------------------+
                        |     Router R2      |
                        |   Branch Router    |
                        +---------+----------+
                                  | Gi0/1
                                  v
                        [ Remote Server 10.0.0.130 ]
                                  ^
                                  | (OSPF Area 0)
        +-------------------------+-------------------------+
        | Gi0/0 (802.1Q Sub-interfaces .10, .20, .30, .40)
        v
+----------------+      Fa0/24 (Trunk)      +----------------+
|   Switch SW1   |<=======================>|   Switch SW2   |
| Catalyst 2960  |                         | Catalyst 2960  |
+---+-----+------+                         +-------+--------+
    |     |     |                                  |
Fa0/1| Fa0/2| Fa0/10|                              | Fa0/5
    |     |     |                                  |
    v     v     v                                  v
 [PC1]  [PC2] [Finance PC]                    [Server 1]
(VLAN10) (VLAN20) (VLAN40)                     (VLAN30)
```

---

## 3. Step-by-Step Instructions to Create the `.pkt` File

### Step 1: Open Cisco Packet Tracer
Launch Cisco Packet Tracer (v7.x, v8.x, or newer) on your computer.

### Step 2: Place Devices on the Canvas
1. **Routers**: Add two **Cisco 2911** (or 1941 / 4321) routers. Name them `R1` and `R2`.
2. **Switches**: Add two **Cisco Catalyst 2960** switches. Name them `SW1` and `SW2`.
3. **End Devices**:
   - Add 3 PCs: `PC1`, `PC2`, and `Finance-PC`.
   - Add 2 Servers: `Server1` and `Remote-Server`.

### Step 3: Cable the Topology
- **Copper Straight-Through Cables**:
  - `R1` **GigabitEthernet0/0** <--> `SW1` **GigabitEthernet0/1**
  - `SW1` **FastEthernet0/1** <--> `PC1` **FastEthernet0**
  - `SW1` **FastEthernet0/2** <--> `PC2` **FastEthernet0**
  - `SW1` **FastEthernet0/10** <--> `Finance-PC` **FastEthernet0**
  - `SW2` **FastEthernet0/5** <--> `Server1` **FastEthernet0**
  - `R2` **GigabitEthernet0/1** <--> `Remote-Server` **FastEthernet0**
- **Copper Cross-Over Cables**:
  - `SW1` **FastEthernet0/24** <--> `SW2` **FastEthernet0/24** (Inter-switch trunk)
  - `R1` **GigabitEthernet0/1** <--> `R2` **GigabitEthernet0/0** (Router-to-router link)

### Step 4: Apply Device Configurations
Open the **CLI** tab for each device and paste the corresponding configuration script:
- For `R1`: Paste contents of `packet_tracer_lab/R1_base.cfg`
- For `R2`: Paste contents of `packet_tracer_lab/R2_base.cfg`
- For `SW1`: Paste contents of `packet_tracer_lab/SW1_base.cfg`
- For `SW2`: Paste contents of `packet_tracer_lab/SW2_base.cfg`

### Step 5: Configure IP Settings on PCs and Servers
- **PC1 (VLAN 10)**: DHCP or Static `192.168.10.50/24`, Gateway: `192.168.10.1`
- **PC2 (VLAN 20)**: DHCP or Static `192.168.20.50/24`, Gateway: `192.168.20.1`
- **Finance-PC (VLAN 40)**: Static `192.168.40.50/24`, Gateway: `192.168.40.1`
- **Server1 (VLAN 30)**: Static `192.168.30.10/24`, Gateway: `192.168.30.1`
- **Remote-Server**: Static `10.0.0.130/25`, Gateway: `10.0.0.129`

### Step 6: Save as `.pkt` File
In Cisco Packet Tracer:
1. Click **File > Save As...**
2. Name the file: `NetSage_AI_Enterprise_Lab.pkt`
3. Click **Save**.

---

## 4. Troubleshooting Lab Scenarios with NetSage AI

When you introduce faults into your `.pkt` lab (e.g., misconfigured VLANs, shutdown interfaces, OSPF timer mismatches, or missing ACL/NAT statements):
1. In Packet Tracer, execute show commands (e.g., `show ip interface brief`, `show ip ospf neighbor`, `show access-lists`).
2. Run NetSage AI locally (`run_netsage.bat` or `streamlit run app.py`).
3. Paste the symptom and show output into the **NetSage Sentinel NOC Console** to get instant, grounded root cause analysis and exact Cisco fix commands.
